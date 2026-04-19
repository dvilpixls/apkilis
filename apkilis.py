#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APKILIS v2.0 - Analizador Forense Profesional de Android
Soporta: APK, APKM, XAPK, APKS
100% Local / Offline
"""

import os, sys, json, shutil, zipfile, hashlib, subprocess, re, stat, signal, logging, tempfile, gc, multiprocessing
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Logging global para diagnóstico post-crash
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        f"{datetime.now().strftime('%Y-%m-%d')}.apkilis.log")
logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("apkilis")


class StepTimeout(Exception):
    """Excepción para timeout de un paso de análisis."""
    pass


def _timeout_handler(signum, frame):
    raise StepTimeout("Paso de análisis excedió el tiempo límite")


def run_with_timeout(func, args=(), kwargs=None, timeout_sec=120):
    """Ejecuta una función con timeout usando señales UNIX."""
    if kwargs is None:
        kwargs = {}
    if os.name != 'posix':
        return func(*args, **kwargs)
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout_sec)
    try:
        result = func(*args, **kwargs)
        signal.alarm(0)
        return result
    except StepTimeout:
        raise
    finally:
        signal.signal(signal.SIGALRM, old_handler)
        signal.alarm(0)


def _subprocess_worker(func, args, kwargs, result_queue):
    """Worker que corre en proceso hijo con RLIMIT_AS aplicado."""
    try:
        import resource
        result = func(*args, **kwargs)
        result_queue.put(("ok", result))
    except MemoryError:
        result_queue.put(("memory_error", None))
    except Exception as e:
        result_queue.put(("error", str(e)))


def _subprocess_target_with_memlimit(func, args, kwargs, result_queue, mem_limit_mb):
    """Top-level target para Process(spawn) — picklable, aplica RLIMIT_AS."""
    import resource
    mem_bytes = mem_limit_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ValueError, resource.error):
        pass  # no fatal: continuar sin límite
    _subprocess_worker(func, args, kwargs, result_queue)


def run_in_subprocess_with_memlimit(func, args=(), kwargs=None,
                                     timeout_sec=180, mem_limit_mb=2560):
    """Ejecuta func en un proceso hijo con límite de memoria virtual (RLIMIT_AS).

    - En POSIX: aplica RLIMIT_AS al hijo; si excede el límite el kernel mata
      al hijo con MemoryError sin afectar al proceso padre.
    - En Windows: cae al comportamiento de run_with_timeout (sin límite de mem).
    - Usa multiprocessing 'spawn' para no heredar estado del padre.
    """
    if kwargs is None:
        kwargs = {}
    if os.name != 'posix':
        return run_with_timeout(func, args=args, kwargs=kwargs,
                                timeout_sec=timeout_sec)

    ctx = multiprocessing.get_context('spawn')
    result_queue = ctx.Queue()

    proc = ctx.Process(
        target=_subprocess_target_with_memlimit,
        args=(func, args, kwargs, result_queue, mem_limit_mb)
    )
    proc.start()
    proc.join(timeout=timeout_sec)

    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=5)
        raise StepTimeout(f"Subprocess excedió {timeout_sec}s")

    if proc.exitcode != 0 and result_queue.empty():
        raise MemoryError(f"Proceso hijo terminó con código {proc.exitcode} "
                          "(probable OOM kill)")

    if result_queue.empty():
        raise RuntimeError("Proceso hijo no devolvió resultado")

    status, value = result_queue.get_nowait()
    if status == "ok":
        return value
    elif status == "memory_error":
        raise MemoryError("Proceso hijo excedió límite de memoria")
    else:
        raise RuntimeError(f"Error en proceso hijo: {value}")

try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    import xml.etree.ElementTree as etree
    HAS_LXML = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.text import Text
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.align import Align
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

try:
    from jinja2 import Template
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

# Androguard - Análisis profundo de APK/DEX desde Python
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.misc import AnalyzeAPK
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False

# Quark-Engine - Motor heurístico de detección de malware
try:
    from quark.report import Report as QuarkReport
    HAS_QUARK = True
except ImportError:
    HAS_QUARK = False

# YARA - Motor de reglas y firmas de malware
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# LIEF - Análisis de binarios ELF (librerías nativas .so)
try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

# cryptography - Análisis profundo de certificados X.509
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Quark-Engine low-level API (carga APK una sola vez)
HAS_QUARK_LOWLEVEL = False
if HAS_QUARK:
    try:
        from quark.core.quark import Quark as QuarkCore
        from quark.core.struct.ruleobject import RuleObject
        HAS_QUARK_LOWLEVEL = True
    except ImportError:
        pass

# Androwarn - Análisis de comportamientos
HAS_ANDROWARN = False
try:
    from androwarn.warn.analysis.analysis import perform_analysis as _androwarn_perform
    HAS_ANDROWARN = True
except ImportError:
    pass

# ssdeep - Fuzzy hashing
HAS_SSDEEP = False
try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    pass

# TLSH - Trend Micro Locality Sensitive Hash
HAS_TLSH = False
try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    pass

import math
import struct as _struct

VERSION = "4.2.0"

# ====================================================================
# BASES DE DATOS LOCALES
# ====================================================================

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": ("CRITICO", "Lectura de SMS"),
    "android.permission.SEND_SMS": ("CRITICO", "Envio de SMS - posible fraude premium"),
    "android.permission.RECEIVE_SMS": ("CRITICO", "Intercepcion de SMS entrantes"),
    "android.permission.READ_CALL_LOG": ("CRITICO", "Lectura del registro de llamadas"),
    "android.permission.READ_CONTACTS": ("ALTO", "Acceso a contactos del usuario"),
    "android.permission.WRITE_CONTACTS": ("ALTO", "Modificacion de contactos"),
    "android.permission.READ_PHONE_STATE": ("ALTO", "Acceso a IMEI, numero, estado"),
    "android.permission.READ_PHONE_NUMBERS": ("ALTO", "Lectura de numeros telefonicos"),
    "android.permission.CALL_PHONE": ("ALTO", "Capacidad de realizar llamadas"),
    "android.permission.RECORD_AUDIO": ("CRITICO", "Grabacion de microfono"),
    "android.permission.CAMERA": ("ALTO", "Acceso a la camara"),
    "android.permission.ACCESS_FINE_LOCATION": ("ALTO", "Ubicacion GPS precisa"),
    "android.permission.ACCESS_COARSE_LOCATION": ("MEDIO", "Ubicacion aproximada"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("CRITICO", "Ubicacion en segundo plano"),
    "android.permission.READ_EXTERNAL_STORAGE": ("MEDIO", "Lectura de almacenamiento"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("MEDIO", "Escritura en almacenamiento"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("ALTO", "Acceso total al almacenamiento"),
    "android.permission.INTERNET": ("BAJO", "Acceso a Internet"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("ALTO", "Ventana sobre apps - overlay attack"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("CRITICO", "Servicio accesibilidad - keylogger potencial"),
    "android.permission.BIND_DEVICE_ADMIN": ("CRITICO", "Administrador de dispositivo"),
    "android.permission.READ_CALENDAR": ("MEDIO", "Lectura de calendario"),
    "android.permission.BODY_SENSORS": ("ALTO", "Acceso a sensores corporales"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("MEDIO", "Auto-inicio al encender"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("ALTO", "Solicitar instalacion de APKs"),
    "android.permission.INSTALL_PACKAGES": ("CRITICO", "Instalar apps silenciosamente"),
    "android.permission.DELETE_PACKAGES": ("ALTO", "Eliminar apps"),
    "android.permission.QUERY_ALL_PACKAGES": ("MEDIO", "Enumerar todas las apps instaladas"),
    "android.permission.CHANGE_WIFI_STATE": ("MEDIO", "Modificar estado WiFi"),
    "android.permission.POST_NOTIFICATIONS": ("BAJO", "Enviar notificaciones"),
}

KNOWN_TRACKERS = {
    "com.google.android.gms.analytics": ("Google Analytics", "Analytics"),
    "com.google.firebase.analytics": ("Firebase Analytics", "Analytics"),
    "com.google.firebase.crashlytics": ("Firebase Crashlytics", "Crash Reporting"),
    "com.google.firebase.messaging": ("Firebase Cloud Messaging", "Push"),
    "com.google.android.gms.ads": ("Google AdMob", "Ads"),
    "com.google.ads": ("Google Ads SDK", "Ads"),
    "com.facebook.ads": ("Facebook Audience Network", "Ads"),
    "com.facebook.appevents": ("Facebook App Events", "Analytics"),
    "com.facebook.login": ("Facebook Login", "Social"),
    "com.appsflyer": ("AppsFlyer", "Attribution"),
    "com.adjust.sdk": ("Adjust", "Attribution"),
    "com.branch.referral": ("Branch.io", "Attribution"),
    "com.crashlytics": ("Crashlytics Legacy", "Crash Reporting"),
    "com.bugsnag": ("Bugsnag", "Crash Reporting"),
    "io.sentry": ("Sentry", "Crash Reporting"),
    "com.newrelic": ("New Relic", "Monitoring"),
    "com.mixpanel": ("Mixpanel", "Analytics"),
    "com.amplitude": ("Amplitude", "Analytics"),
    "com.flurry": ("Flurry", "Analytics"),
    "com.segment": ("Segment", "Analytics"),
    "com.braze": ("Braze", "Marketing"),
    "com.onesignal": ("OneSignal", "Push"),
    "com.unity3d.ads": ("Unity Ads", "Ads"),
    "com.vungle": ("Vungle", "Ads"),
    "com.inmobi": ("InMobi", "Ads"),
    "com.applovin": ("AppLovin", "Ads"),
    "com.chartboost": ("Chartboost", "Ads"),
    "com.ironsource": ("IronSource", "Ads"),
    "com.adcolony": ("AdColony", "Ads"),
    "com.tapjoy": ("Tapjoy", "Ads"),
    "com.startapp": ("StartApp", "Ads"),
    "com.amazon.device.ads": ("Amazon Ads", "Ads"),
    "com.tencent": ("Tencent SDK", "Social/Ads"),
    "com.huawei.hms": ("Huawei Mobile Services", "Various"),
    "com.umeng": ("Umeng (Alibaba)", "Analytics"),
    "com.clevertap": ("CleverTap", "Analytics"),
    "com.pushwoosh": ("Pushwoosh", "Push"),
    "com.instabug": ("Instabug", "Bug Reporting"),
    "com.stripe": ("Stripe", "Payment"),
    "com.braintreepayments": ("Braintree", "Payment"),
    "com.paypal": ("PayPal", "Payment"),
    "com.google.android.gms.maps": ("Google Maps", "Maps"),
    "com.scottyab.rootbeer": ("RootBeer", "Security"),
    "com.squareup.okhttp": ("OkHttp", "Networking"),
    "com.squareup.retrofit": ("Retrofit", "Networking"),
    "io.reactivex": ("RxJava", "Reactive"),
    # --- Empresas israelíes de vigilancia / spyware ---
    "com.nsogroup": ("NSO Group (Pegasus)", "Israeli Surveillance"),
    "com.circlestech": ("Circles Technologies (NSO)", "Israeli Surveillance"),
    "com.candiru": ("Candiru (DevilsTongue)", "Israeli Surveillance"),
    "com.saito.tech": ("Candiru/Saito Tech", "Israeli Surveillance"),
    "com.cybereason": ("Cybereason", "Israeli Security/Telemetry"),
    "com.cognyte": ("Cognyte (Verint)", "Israeli Surveillance"),
    "com.verint": ("Verint Systems", "Israeli Surveillance"),
    "com.cellebrite": ("Cellebrite UFED", "Israeli Forensics"),
    "com.paragon": ("Paragon Solutions (Graphite)", "Israeli Surveillance"),
    "com.quadream": ("QuaDream (Reign)", "Israeli Surveillance"),
    "com.intellexa": ("Intellexa (Predator)", "Israeli/EU Surveillance"),
    "com.septier": ("Septier Communication", "Israeli Interception"),
    "com.ability.inc": ("Ability Inc (ULIN)", "Israeli Interception"),
    "com.wintego": ("Wintego (CatchApp)", "Israeli Surveillance"),
    "com.picsix": ("PicSix (WiFi intercept)", "Israeli Interception"),
    "com.cobwebs": ("Cobwebs Technologies", "Israeli OSINT"),
    "com.mer.group": ("Mer Group (formerly Nice)", "Israeli Surveillance"),
    "com.elbit.systems": ("Elbit Systems", "Israeli Defense/Cyber"),
    "com.checkpoint": ("Check Point", "Israeli Security"),
    "com.toka.cyber": ("Toka (IoT hacking)", "Israeli Surveillance"),
    "com.nemesystech": ("Nemesys (formerly Trovicor IL)", "Israeli Surveillance"),
    # --- Otros trackers/SDKs de vigilancia global ---
    "com.gamma.group": ("Gamma Group (FinFisher)", "Surveillance"),
    "com.hackingteam": ("Hacking Team (Galileo)", "Surveillance"),
    "com.appin.tech": ("Appin Technologies", "Surveillance"),
    "com.wolf.intelligence": ("Wolf Intelligence", "Surveillance"),
    "com.dji.sdk": ("DJI SDK", "Chinese Telemetry"),
    "com.bytedance": ("ByteDance/TikTok SDK", "Chinese Telemetry"),
}

SUSPICIOUS_CODE_PATTERNS = {
    "Runtime.exec": {"pattern": r"Ljava/lang/Runtime;->exec", "severity": "ALTO", "desc": "Ejecucion de comandos del sistema"},
    "ProcessBuilder": {"pattern": r"Ljava/lang/ProcessBuilder;", "severity": "ALTO", "desc": "Construccion de procesos del sistema"},
    "DexClassLoader": {"pattern": r"Ldalvik/system/DexClassLoader;", "severity": "CRITICO", "desc": "Carga dinamica de codigo DEX"},
    "InMemoryDex": {"pattern": r"Ldalvik/system/InMemoryDexClassLoader;", "severity": "CRITICO", "desc": "Carga de DEX en memoria (evasion)"},
    "Reflection": {"pattern": r"Ljava/lang/reflect/", "severity": "MEDIO", "desc": "Uso de reflexion Java"},
    "Cipher_DES": {"pattern": r'const-string.*"DES"', "severity": "ALTO", "desc": "Cifrado DES (inseguro)"},
    "Cipher_ECB": {"pattern": r'const-string.*"ECB"', "severity": "ALTO", "desc": "Modo ECB (inseguro)"},
    "Cipher_MD5": {"pattern": r'const-string.*"MD5"', "severity": "MEDIO", "desc": "Hash MD5 (debil)"},
    "WebView_JS": {"pattern": r"setJavaScriptEnabled", "severity": "MEDIO", "desc": "WebView con JavaScript habilitado"},
    "WebView_JSInterface": {"pattern": r"addJavascriptInterface", "severity": "ALTO", "desc": "WebView con JavascriptInterface (puente nativo)"},
    "WebView_FileAccess": {"pattern": r"setAllowFileAccess", "severity": "ALTO", "desc": "WebView con acceso a archivos"},
    "WebView_Universal": {"pattern": r"setAllowUniversalAccessFromFileURLs", "severity": "CRITICO", "desc": "WebView acceso universal file://"},
    "TrustAllCerts": {"pattern": r"TrustAll|ALLOW_ALL_HOSTNAME|trustAllCerts|X509TrustManager", "severity": "CRITICO", "desc": "Validacion SSL deshabilitada (MitM)"},
    "Base64_Decode": {"pattern": r"Landroid/util/Base64;->decode", "severity": "MEDIO", "desc": "Decodificacion Base64 (ofuscacion)"},
    "Native_Load": {"pattern": r"System;->loadLibrary|System;->load\(", "severity": "MEDIO", "desc": "Carga de biblioteca nativa (.so)"},
    "Root_Detection": {"pattern": r'const-string.*"/system/app/Superuser"|const-string.*"/system/xbin/su"|const-string.*"test-keys"', "severity": "INFO", "desc": "Deteccion de root"},
    "Emulator_Detection": {"pattern": r'const-string.*"goldfish"|const-string.*"generic"|const-string.*"sdk_gphone"', "severity": "INFO", "desc": "Deteccion de emulador"},
    "Clipboard": {"pattern": r"ClipboardManager;->getPrimaryClip", "severity": "MEDIO", "desc": "Acceso al portapapeles"},
    "Accessibility": {"pattern": r"AccessibilityService|AccessibilityEvent", "severity": "ALTO", "desc": "Servicio de accesibilidad"},
    "DeviceAdmin": {"pattern": r"DeviceAdminReceiver|DevicePolicyManager", "severity": "ALTO", "desc": "Funciones admin de dispositivo"},
    "SMS_Send": {"pattern": r"SmsManager;->sendTextMessage|SmsManager;->sendMultipartTextMessage", "severity": "CRITICO", "desc": "Envio programatico de SMS"},
    "PackageInstall": {"pattern": r"ACTION_INSTALL_PACKAGE", "severity": "ALTO", "desc": "Instalacion programatica de paquetes"},
    "SharedPreferences": {"pattern": r"getSharedPreferences", "severity": "INFO", "desc": "Uso de SharedPreferences"},
    "SQLiteDatabase": {"pattern": r"Landroid/database/sqlite/SQLiteDatabase;", "severity": "INFO", "desc": "Base de datos SQLite local"},
}

SECRET_PATTERNS = {
    "URL": re.compile(r'https?://[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+'),
    "IP_Address": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'),
    "Email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "AWS_Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "Google_API_Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Firebase_URL": re.compile(r'https://[\w-]+\.firebaseio\.com'),
    "Generic_API_Key": re.compile(r'(?i)(?:api[_-]?key|apikey|api_secret|secret_key|auth_token|access_token)\s*[=:]\s*["\']([A-Za-z0-9\-._~+/=]{16,})["\']'),
    "JWT_Token": re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+'),
    "Private_Key": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    "Hardcoded_Password": re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    "SQL_Query": re.compile(r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.{10,}(?:FROM|INTO|TABLE|SET|WHERE)'),
    "Connection_String": re.compile(r'(?i)(?:jdbc|mongodb|mysql|postgres|redis|amqp)://[^\s"\']+'),
    "Telegram_Bot": re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b'),
    "GitHub_Token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
}

IGNORE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "10.0.0.1", "192.168.1.1", "224.0.0.1"}
IGNORE_URL_RE = [re.compile(p) for p in [
    r'schemas\.android\.com', r'www\.w3\.org', r'ns\.adobe\.com',
    r'xmlpull\.org', r'xml\.org', r'apache\.org/xml', r'schemas\.microsoft\.com',
]]

# Dominios / TLDs asociados a vigilancia y exfiltración israelí
ISRAELI_SURVEILLANCE_DOMAINS = {
    ".co.il", ".org.il", ".net.il", ".ac.il", ".muni.il",
}
ISRAELI_SURVEILLANCE_KEYWORDS = [
    "nsogroup", "candiru", "circlestech", "cybereason", "cognyte",
    "cellebrite", "paragon", "quadream", "intellexa", "septier",
    "verint", "toka", "cobwebs", "elbit", "mer-group", "nemesys",
    "saito-tech", "pegasus", "devilstongue", "graphite", "reign",
    "predator", "finspy", "finfisher",
]

# Patrones de backdoor / C2 en código smali y nativo
BACKDOOR_C2_PATTERNS = {
    "ReverseShell_Socket": {
        "pattern": r"Ljava/net/Socket;->.*?Ljava/lang/Runtime;->exec",
        "severity": "CRITICO",
        "desc": "Posible reverse shell: Socket + Runtime.exec combinados",
        "category": "backdoor",
    },
    "C2_ScheduledTask": {
        "pattern": r"ScheduledExecutorService|ScheduledThreadPoolExecutor.*?HttpURLConnection|OkHttp",
        "severity": "ALTO",
        "desc": "Tarea programada con conexión HTTP (posible beacon C2)",
        "category": "c2_beacon",
    },
    "C2_AlarmManager_Net": {
        "pattern": r"AlarmManager;->setRepeating.*?HttpURLConnection|URLConnection",
        "severity": "ALTO",
        "desc": "AlarmManager con conexiones de red repetitivas (beacon pattern)",
        "category": "c2_beacon",
    },
    "DGA_Random_Domain": {
        "pattern": r'Random;->next.*?StringBuilder;->append.*?\.connect|\.openConnection',
        "severity": "CRITICO",
        "desc": "Posible DGA: generación aleatoria + conexión de red",
        "category": "dga",
    },
    "Hidden_DexClassLoader": {
        "pattern": r"Base64;->decode.*?DexClassLoader|InMemoryDexClassLoader",
        "severity": "CRITICO",
        "desc": "Carga dinámica de DEX desde datos Base64 (payload oculto)",
        "category": "backdoor",
    },
    "Encrypted_C2_Config": {
        "pattern": r'Cipher;->getInstance.*?const-string.*?(AES|Blowfish|RC4).*?HttpURLConnection|OkHttp',
        "severity": "ALTO",
        "desc": "Configuración cifrada + conexión de red (posible C2 cifrado)",
        "category": "c2_encrypted",
    },
    "Socket_RawConnect": {
        "pattern": r"Ljava/net/Socket;-><init>\(Ljava/lang/String;I\)",
        "severity": "ALTO",
        "desc": "Conexión socket raw directa (IP + puerto)",
        "category": "c2_raw",
    },
    "DataOutputStream_Socket": {
        "pattern": r"DataOutputStream;-><init>.*?Socket;->getOutputStream",
        "severity": "ALTO",
        "desc": "Escritura de datos binarios a socket (exfiltración/C2)",
        "category": "exfiltration",
    },
    "Steganography_Bitmap": {
        "pattern": r"BitmapFactory;->decode.*?getPixel|setPixel",
        "severity": "MEDIO",
        "desc": "Manipulación de píxeles en bitmap (posible esteganografía)",
        "category": "steganography",
    },
    "SMS_C2_Channel": {
        "pattern": r"SmsManager;->send.*?BroadcastReceiver.*?SMS_RECEIVED",
        "severity": "CRITICO",
        "desc": "Canal C2 vía SMS: envía y recibe SMS programáticamente",
        "category": "c2_sms",
    },
    "Accessibility_Keylogger": {
        "pattern": r"AccessibilityService.*?onAccessibilityEvent.*?getText|getContentDescription",
        "severity": "CRITICO",
        "desc": "Keylogger vía AccessibilityService: captura texto de pantalla",
        "category": "keylogger",
    },
    "Screen_Capture": {
        "pattern": r"MediaProjection|createScreenCaptureIntent|createVirtualDisplay",
        "severity": "ALTO",
        "desc": "Captura de pantalla programática (spyware)",
        "category": "spyware",
    },
    "Camera_Silent": {
        "pattern": r"Camera;->takePicture|CameraCaptureSession.*?capture",
        "severity": "ALTO",
        "desc": "Captura de cámara silenciosa",
        "category": "spyware",
    },
    "Microphone_Record": {
        "pattern": r"AudioRecord;->startRecording|MediaRecorder;->start.*?setAudioSource",
        "severity": "ALTO",
        "desc": "Grabación de micrófono (spyware/vigilancia)",
        "category": "spyware",
    },
    "Location_Exfiltration": {
        "pattern": r"LocationManager;->getLastKnownLocation.*?HttpURLConnection|URLConnection",
        "severity": "CRITICO",
        "desc": "Obtención de ubicación + envío por red (exfiltración GPS)",
        "category": "exfiltration",
    },
    "Contacts_Exfiltration": {
        "pattern": r"ContactsContract.*?query.*?HttpURLConnection|URLConnection|OutputStream",
        "severity": "CRITICO",
        "desc": "Lectura de contactos + envío por red (exfiltración)",
        "category": "exfiltration",
    },
    "CallLog_Exfiltration": {
        "pattern": r"CallLog.*?query.*?HttpURLConnection|URLConnection|OutputStream",
        "severity": "CRITICO",
        "desc": "Lectura de registro de llamadas + envío por red",
        "category": "exfiltration",
    },
    "SMS_Exfiltration": {
        "pattern": r'content://sms.*?query.*?HttpURLConnection|URLConnection|OutputStream',
        "severity": "CRITICO",
        "desc": "Lectura de SMS + envío por red (exfiltración)",
        "category": "exfiltration",
    },
    "Clipboard_Exfiltration": {
        "pattern": r"ClipboardManager;->getPrimaryClip.*?HttpURLConnection|URLConnection",
        "severity": "ALTO",
        "desc": "Lectura de portapapeles + envío por red",
        "category": "exfiltration",
    },
    "WakeLock_Persistent": {
        "pattern": r"PowerManager;->newWakeLock.*?PARTIAL_WAKE_LOCK",
        "severity": "MEDIO",
        "desc": "WakeLock parcial persistente (mantiene CPU activo en background)",
        "category": "persistence",
    },
    "Boot_Persistence": {
        "pattern": r"BOOT_COMPLETED.*?BroadcastReceiver|Service;->onStartCommand",
        "severity": "MEDIO",
        "desc": "Persistencia al arranque del dispositivo",
        "category": "persistence",
    },
    "Foreground_Stealth_Service": {
        "pattern": r"startForeground.*?Notification.*?PRIORITY_MIN|setSmallIcon\(0\)",
        "severity": "ALTO",
        "desc": "Servicio foreground con notificación oculta (stealth)",
        "category": "evasion",
    },
}

# Patrones para clasificar endpoints extraídos
ENDPOINT_CLASSIFICATION = {
    "c2_ports": {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345,
                 4443, 8443, 8080, 9090, 1234, 6667, 6697, 65535, 55555},
    "suspicious_tlds": {
        ".onion", ".i2p", ".bit", ".bazar", ".coin", ".lib", ".emc",
        ".tk", ".ml", ".ga", ".cf", ".gq",  # TLDs gratis usados en phishing
    },
    "legitimate_domains": {
        "google.com", "googleapis.com", "gstatic.com", "android.com",
        "facebook.com", "fbcdn.net", "apple.com", "microsoft.com",
        "amazonaws.com", "cloudfront.net", "akamai.net", "cloudflare.com",
        "github.com", "stackoverflow.com", "mozilla.org",
    },
    "vpn_proxy_keywords": [
        "vpn", "proxy", "socks", "tor", "tunnel", "anonymo",
        "hide", "mask", "bypass",
    ],
}

# Mapeo: permiso → datos accedidos → APIs que los leen
PERMISSION_DATA_MAP = {
    "android.permission.READ_SMS": {
        "data_type": "SMS/MMS",
        "read_apis": ["content://sms", "Telephony.Sms", "SmsMessage;->getMessageBody"],
        "severity": "CRITICO",
    },
    "android.permission.READ_CONTACTS": {
        "data_type": "Contactos",
        "read_apis": ["ContactsContract", "content://contacts", "content://com.android.contacts"],
        "severity": "ALTO",
    },
    "android.permission.READ_CALL_LOG": {
        "data_type": "Registro de llamadas",
        "read_apis": ["CallLog", "content://call_log"],
        "severity": "CRITICO",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "data_type": "Ubicación GPS",
        "read_apis": ["LocationManager", "FusedLocationProvider", "getLastKnownLocation", "requestLocationUpdates"],
        "severity": "ALTO",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "data_type": "Ubicación aproximada",
        "read_apis": ["LocationManager", "getLastKnownLocation"],
        "severity": "MEDIO",
    },
    "android.permission.CAMERA": {
        "data_type": "Cámara (fotos/video)",
        "read_apis": ["Camera;->open", "CameraManager;->openCamera", "CameraCaptureSession"],
        "severity": "ALTO",
    },
    "android.permission.RECORD_AUDIO": {
        "data_type": "Micrófono (audio)",
        "read_apis": ["AudioRecord", "MediaRecorder;->setAudioSource"],
        "severity": "CRITICO",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "data_type": "Archivos del usuario",
        "read_apis": ["Environment;->getExternalStorageDirectory", "MediaStore", "content://media"],
        "severity": "MEDIO",
    },
    "android.permission.READ_CALENDAR": {
        "data_type": "Calendario",
        "read_apis": ["CalendarContract", "content://calendar"],
        "severity": "MEDIO",
    },
    "android.permission.READ_PHONE_STATE": {
        "data_type": "IMEI/IMSI/Número telefónico",
        "read_apis": ["TelephonyManager;->getDeviceId", "getSubscriberId", "getLine1Number", "getImei"],
        "severity": "ALTO",
    },
    "android.permission.BODY_SENSORS": {
        "data_type": "Sensores corporales",
        "read_apis": ["SensorManager", "TYPE_HEART_RATE"],
        "severity": "ALTO",
    },
}

# APIs de red que indican envío/exfiltración de datos
NETWORK_EXFIL_APIS = [
    "HttpURLConnection;->connect",
    "HttpURLConnection;->getOutputStream",
    "HttpsURLConnection;->connect",
    "HttpsURLConnection;->getOutputStream",
    "URLConnection;->getOutputStream",
    "OkHttpClient",
    "Retrofit",
    "Volley",
    "Socket;->getOutputStream",
    "DataOutputStream",
    "HttpPost",
    "HttpPut",
    "MultipartEntity",
    "BufferedWriter.*?OutputStreamWriter.*?Socket",
]

# ====================================================================
# UTILIDADES
# ====================================================================

def rprint(msg, style=""):
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        print(msg)

def compute_hashes(filepath):
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}

def file_metadata(filepath):
    st = os.stat(filepath)
    return {
        "size_bytes": st.st_size,
        "size_human": format_size(st.st_size),
        "created": datetime.fromtimestamp(st.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
        "mime_type": get_mime_type(filepath),
    }

def format_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

def get_mime_type(filepath):
    try:
        result = subprocess.run(["file", "--mime-type", "-b", filepath],
                                capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return "unknown"

def get_desktop_path():
    return os.path.join(os.path.expanduser("~"), "Escritorio")


# ====================================================================
# BANNER
# ====================================================================

BANNER_ART = r"""
     ██████╗ ██████╗ ██╗  ██╗██╗██╗     ██╗███████╗
    ██╔══██╗██╔══██╗██║ ██╔╝██║██║     ██║██╔════╝
    ███████║██████╔╝█████╔╝ ██║██║     ██║███████╗
    ██╔══██║██╔═══╝ ██╔═██╗ ██║██║     ██║╚════██║
    ██║  ██║██║     ██║  ██╗██║███████╗██║███████║
    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚══════╝
"""

def show_banner():
    os.system("clear" if os.name == "posix" else "cls")
    if HAS_RICH:
        console.print(Panel(
            Text(BANNER_ART, style="bold cyan", justify="center"),
            title=f"[bold red]APKILIS v{VERSION}[/bold red]",
            subtitle="[yellow]Analizador Forense Android - 100% Offline[/yellow]",
            border_style="bright_blue",
            box=box.DOUBLE_EDGE, padding=(0, 2),
        ))
    else:
        print(BANNER_ART)
        print(f"  [ APKILIS v{VERSION} - Analizador Forense Android - 100% Offline ]")
        print("  " + "=" * 60 + "\n")


# ====================================================================
# MODULO 1: EXTRACCION DE BUNDLES
# ====================================================================

class BundleExtractor:
    @staticmethod
    def extract(target_file, extract_dir):
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(target_file, 'r') as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            rprint("[X] Archivo ZIP corrupto.", style="bold red")
            return None, [], {}

        all_apks = []
        for root, _, files in os.walk(extract_dir):
            for f in files:
                if f.lower().endswith('.apk'):
                    all_apks.append(os.path.join(root, f))

        base_apk = None
        for apk in all_apks:
            name = os.path.basename(apk).lower()
            if name in ('base.apk', 'main.apk', 'app.apk') or 'base' in name:
                base_apk = apk
                break

        if not base_apk and all_apks:
            base_apk = max(all_apks, key=os.path.getsize)

        split_apks = [a for a in all_apks if a != base_apk]

        bundle_meta = {}
        manifest_json = os.path.join(extract_dir, "manifest.json")
        if os.path.exists(manifest_json):
            try:
                with open(manifest_json, 'r') as f:
                    bundle_meta = json.load(f)
            except Exception:
                logger.debug("Error leyendo manifest.json del bundle")
                pass

        return base_apk, split_apks, bundle_meta

    @staticmethod
    def inventory(extract_dir):
        inventory = defaultdict(list)
        for root, _, files in os.walk(extract_dir):
            for f in files:
                fp = os.path.join(root, f)
                ext = Path(f).suffix.lower() or "(sin ext)"
                rel = os.path.relpath(fp, extract_dir)
                inventory[ext].append({"path": rel, "size": format_size(os.path.getsize(fp))})
        return dict(inventory)


# ====================================================================
# MODULO 2: CERTIFICADO / FIRMA
# ====================================================================

class CertAnalyzer:
    @staticmethod
    def analyze(apk_path):
        result = {"is_signed": False, "signature_valid": False, "signer_info": {},
                  "v1_signed": False, "v2_signed": False, "errors": []}

        try:
            proc = subprocess.run(["jarsigner", "-verify", "-verbose", "-certs", apk_path],
                                  capture_output=True, text=True, timeout=60)
            output = proc.stdout + proc.stderr
            if "jar verified" in output.lower():
                result["is_signed"] = True
                result["signature_valid"] = True
                result["v1_signed"] = True
            elif "jar is unsigned" not in output.lower():
                result["is_signed"] = True
                result["v1_signed"] = True
        except Exception as e:
            result["errors"].append(f"jarsigner: {e}")

        try:
            cert_info = CertAnalyzer._extract_cert_info(apk_path)
            if cert_info:
                result["signer_info"] = cert_info
                result["is_signed"] = True
        except Exception as e:
            result["errors"].append(f"keytool: {e}")

        try:
            result["v2_signed"] = CertAnalyzer._check_v2(apk_path)
        except Exception as e:
            logger.debug(f"Error verificando firma V2: {e}")

        return result

    @staticmethod
    def _extract_cert_info(apk_path):
        info = {}
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                cert_files = [n for n in zf.namelist()
                              if n.startswith("META-INF/") and
                              any(n.endswith(e) for e in (".RSA", ".DSA", ".EC"))]
                if not cert_files:
                    return info
                with tempfile.NamedTemporaryFile(suffix=".cert", delete=False) as tmp:
                    tmp.write(zf.read(cert_files[0]))
                    tmp_path = tmp.name

            proc = subprocess.run(["keytool", "-printcert", "-file", tmp_path],
                                  capture_output=True, text=True, timeout=30)
            os.unlink(tmp_path)

            for line in proc.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Owner:"): info["owner"] = line[6:].strip()
                elif line.startswith("Issuer:"): info["issuer"] = line[7:].strip()
                elif line.startswith("Serial number:"): info["serial"] = line[14:].strip()
                elif line.startswith("Valid from:"): info["validity"] = line[11:].strip()
                elif "SHA1:" in line: info["sha1_fingerprint"] = line.split("SHA1:")[1].strip()
                elif "SHA256:" in line: info["sha256_fingerprint"] = line.split("SHA256:")[1].strip()
                elif "Signature algorithm" in line and ":" in line:
                    info["algorithm"] = line.split(":", 1)[1].strip()
        except Exception as e:
            info["error"] = str(e)
        return info

    @staticmethod
    def _check_v2(apk_path):
        try:
            with open(apk_path, "rb") as f:
                f.seek(0, 2)
                fsize = f.tell()
                search_start = max(0, fsize - 4096)
                f.seek(search_start)
                data = f.read()
                return b"APK Sig Block 42" in data
        except Exception:
            return False


# ====================================================================
# MODULO 3: ANALISIS DEL MANIFEST
# ====================================================================

class ManifestAnalyzer:
    NS = "http://schemas.android.com/apk/res/android"

    @staticmethod
    def analyze(decompiled_dir):
        manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return {"error": "AndroidManifest.xml no encontrado"}

        result = {
            "package": "", "version_name": "", "version_code": "",
            "min_sdk": "", "target_sdk": "", "compile_sdk": "",
            "permissions": [], "custom_permissions": [],
            "activities": [], "services": [], "receivers": [], "providers": [],
            "exported_components": [], "flags": {}, "dangerous_permission_details": [],
        }

        try:
            tree = etree.parse(manifest_path)
            root = tree.getroot()
        except Exception as e:
            return {"error": f"Error parseando manifest: {e}"}

        ns = ManifestAnalyzer.NS

        result["package"] = root.get("package", "")
        result["version_name"] = root.get(f"{{{ns}}}versionName", "")
        result["version_code"] = root.get(f"{{{ns}}}versionCode", "")

        for uses_sdk in root.iter("uses-sdk"):
            result["min_sdk"] = uses_sdk.get(f"{{{ns}}}minSdkVersion", "")
            result["target_sdk"] = uses_sdk.get(f"{{{ns}}}targetSdkVersion", "")

        for perm in root.iter("uses-permission"):
            pname = perm.get(f"{{{ns}}}name", "")
            if pname:
                result["permissions"].append(pname)
                if pname in DANGEROUS_PERMISSIONS:
                    sev, desc = DANGEROUS_PERMISSIONS[pname]
                    result["dangerous_permission_details"].append(
                        {"permission": pname, "severity": sev, "description": desc})

        for perm in root.iter("permission"):
            pname = perm.get(f"{{{ns}}}name", "")
            plevel = perm.get(f"{{{ns}}}protectionLevel", "normal")
            if pname:
                result["custom_permissions"].append({"name": pname, "level": plevel})

        for app in root.iter("application"):
            result["flags"]["debuggable"] = app.get(f"{{{ns}}}debuggable", "false") == "true"
            result["flags"]["allowBackup"] = app.get(f"{{{ns}}}allowBackup", "true") == "true"
            result["flags"]["usesCleartextTraffic"] = app.get(f"{{{ns}}}usesCleartextTraffic", "false") == "true"
            result["flags"]["networkSecurityConfig"] = app.get(f"{{{ns}}}networkSecurityConfig", "")
            result["flags"]["largeHeap"] = app.get(f"{{{ns}}}largeHeap", "false") == "true"

        for tag, key in [("activity","activities"),("service","services"),("receiver","receivers"),("provider","providers")]:
            for elem in root.iter(tag):
                name = elem.get(f"{{{ns}}}name", "")
                exported = elem.get(f"{{{ns}}}exported", "")
                permission = elem.get(f"{{{ns}}}permission", "")

                filters = []
                for intent_filter in elem.iter("intent-filter"):
                    actions = [a.get(f"{{{ns}}}name", "") for a in intent_filter.iter("action")]
                    categories = [c.get(f"{{{ns}}}name", "") for c in intent_filter.iter("category")]
                    data_elems = []
                    for d in intent_filter.iter("data"):
                        data_elems.append({"scheme": d.get(f"{{{ns}}}scheme",""), "host": d.get(f"{{{ns}}}host","")})
                    filters.append({"actions": actions, "categories": categories, "data": data_elems})

                component = {"name": name, "exported": exported, "permission": permission, "intent_filters": filters}
                result[key].append(component)

                is_exported = exported == "true" or (exported == "" and len(filters) > 0)
                if is_exported:
                    result["exported_components"].append({
                        "type": tag, "name": name, "permission": permission,
                        "has_intent_filter": len(filters) > 0, "protected": bool(permission),
                    })

        return result

# ====================================================================
# MODULO 4: SEGURIDAD DE RED
# ====================================================================

class NetworkSecurityAnalyzer:
    @staticmethod
    def analyze(decompiled_dir):
        result = {"has_config": False, "cleartext_permitted": None,
                  "trust_user_certs": False, "certificate_pinning": [],
                  "domain_configs": [], "raw_config": ""}

        config_path = None
        for candidate in [
            os.path.join(decompiled_dir, "res", "xml", "network_security_config.xml"),
            os.path.join(decompiled_dir, "res", "xml", "network_security_configuration.xml"),
        ]:
            if os.path.exists(candidate):
                config_path = candidate
                break

        if not config_path:
            return result

        result["has_config"] = True
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                result["raw_config"] = f.read()

            tree = etree.parse(config_path)
            root = tree.getroot()

            for base_cfg in root.iter("base-config"):
                ct = base_cfg.get("cleartextTrafficPermitted", "")
                if ct:
                    result["cleartext_permitted"] = ct.lower() == "true"
                for trust in base_cfg.iter("trust-anchors"):
                    for cert in trust.iter("certificates"):
                        src = cert.get("src", "")
                        if src == "user":
                            result["trust_user_certs"] = True

            for domain_cfg in root.iter("domain-config"):
                ct = domain_cfg.get("cleartextTrafficPermitted", "")
                domains = [d.text for d in domain_cfg.iter("domain") if d.text]
                pins = []
                for pin_set in domain_cfg.iter("pin-set"):
                    exp = pin_set.get("expiration", "")
                    for pin in pin_set.iter("pin"):
                        pins.append({"digest": pin.get("digest",""), "value": pin.text, "expiration": exp})
                result["domain_configs"].append({"domains": domains, "cleartext": ct, "pins": pins})
                if pins:
                    result["certificate_pinning"].extend(pins)

        except Exception as e:
            result["error"] = str(e)
        return result


# ====================================================================
# MODULO 5: EXTRACCION DE SECRETOS
# ====================================================================

class SecretsExtractor:
    @staticmethod
    def extract(decompiled_dir, progress_callback=None):
        secrets = defaultdict(set)
        scan_exts = {'.smali', '.xml', '.json', '.properties', '.yml', '.yaml', '.txt', '.cfg', '.js', '.html'}

        all_files = []
        for root, _, files in os.walk(decompiled_dir):
            for f in files:
                if Path(f).suffix.lower() in scan_exts:
                    all_files.append(os.path.join(root, f))

        files_scanned = 0
        for filepath in all_files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
                for stype, pattern in SECRET_PATTERNS.items():
                    matches = pattern.findall(content)
                    for match in matches:
                        val = match if isinstance(match, str) else (match[0] if match else "")
                        if not val or len(val) < 4:
                            continue
                        if stype == "IP_Address" and val in IGNORE_IPS:
                            continue
                        if stype == "URL" and any(r.search(val) for r in IGNORE_URL_RE):
                            continue
                        secrets[stype].add(val)
                files_scanned += 1
            except Exception as e:
                logger.debug(f"Error escaneando secretos en {filepath}: {e}")
                continue

        return {k: sorted(list(v)) for k, v in secrets.items()}, files_scanned


# ====================================================================
# MODULO 6: DETECCION DE TRACKERS
# ====================================================================

class TrackerDetector:
    @staticmethod
    def detect(decompiled_dir):
        detected = []
        smali_dirs = [d for d in os.listdir(decompiled_dir) if d.startswith("smali")]

        for tracker_pkg, (name, category) in KNOWN_TRACKERS.items():
            pkg_path = tracker_pkg.replace(".", os.sep)
            for smali_dir in smali_dirs:
                full_path = os.path.join(decompiled_dir, smali_dir, pkg_path)
                if os.path.exists(full_path):
                    detected.append({"name": name, "package": tracker_pkg, "category": category})
                    break

        by_category = defaultdict(list)
        for t in detected:
            by_category[t["category"]].append(t)

        return {"trackers": detected, "by_category": dict(by_category), "total": len(detected)}


# ====================================================================
# MODULO 7: ANALISIS DE CODIGO SMALI
# ====================================================================

class SmaliAnalyzer:
    @staticmethod
    def analyze(decompiled_dir, progress_callback=None):
        findings = []
        smali_files = []
        for root, _, files in os.walk(decompiled_dir):
            for f in files:
                if f.endswith('.smali'):
                    smali_files.append(os.path.join(root, f))

        compiled = {}
        for name, info in SUSPICIOUS_CODE_PATTERNS.items():
            try:
                compiled[name] = (re.compile(info["pattern"]), info["severity"], info["desc"])
            except re.error:
                continue

        files_scanned = 0
        for smali_file in smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, decompiled_dir)
                for name, (pattern, severity, desc) in compiled.items():
                    matches = pattern.findall(content)
                    if matches:
                        findings.append({"name": name, "severity": severity,
                                         "description": desc, "file": rel_path, "count": len(matches)})
                files_scanned += 1
            except Exception as e:
                logger.debug(f"Error analizando smali {smali_file}: {e}")
                continue

        grouped = defaultdict(lambda: {"count": 0, "files": [], "severity": "", "description": ""})
        for f in findings:
            key = f["name"]
            grouped[key]["count"] += f["count"]
            grouped[key]["files"].append(f["file"])
            grouped[key]["severity"] = f["severity"]
            grouped[key]["description"] = f["description"]

        return {"findings": findings, "grouped": dict(grouped),
                "files_scanned": files_scanned, "total_findings": len(findings)}


# ====================================================================
# MODULO 8: ANALISIS DE ESTRUCTURA
# ====================================================================

class StructureAnalyzer:
    @staticmethod
    def analyze(apk_path, decompiled_dir):
        result = {"dex_files": [], "native_libs": [], "architectures": [],
                  "assets": [], "suspicious_assets": [], "total_files": 0, "total_size": 0}

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                archs = set()
                for info in zf.infolist():
                    result["total_files"] += 1
                    result["total_size"] += info.file_size
                    name = info.filename

                    if name.endswith('.dex'):
                        result["dex_files"].append({"name": name, "size": format_size(info.file_size)})

                    elif name.endswith('.so'):
                        parts = name.split('/')
                        arch = parts[1] if len(parts) > 2 and parts[0] == 'lib' else "unknown"
                        archs.add(arch)
                        result["native_libs"].append({"name": os.path.basename(name), "path": name,
                                                      "arch": arch, "size": format_size(info.file_size)})

                    elif name.startswith('assets/'):
                        result["assets"].append(name)
                        ext = Path(name).suffix.lower()
                        sus_exts = {'.apk', '.dex', '.jar', '.so', '.bin', '.dat', '.db',
                                    '.sqlite', '.zip', '.enc', '.key', '.sh', '.py', '.lua', '.elf'}
                        if ext in sus_exts:
                            result["suspicious_assets"].append({"path": name, "extension": ext,
                                                                "size": format_size(info.file_size)})
                result["architectures"] = sorted(list(archs))
        except Exception as e:
            result["error"] = str(e)

        result["total_size_human"] = format_size(result["total_size"])
        return result

# ====================================================================
# MODULO 8B: ANDROGUARD - ANALISIS PROFUNDO DEX/APK
# ====================================================================

class AndroguardAnalyzer:
    """Análisis profundo usando Androguard: clases, métodos, strings, APIs peligrosas."""

    DANGEROUS_APIS = {
        "Ljavax/crypto/Cipher;->getInstance": ("Crypto", "MEDIO", "Uso de cifrado"),
        "Ljavax/crypto/spec/SecretKeySpec;->": ("Crypto", "MEDIO", "Generación de clave secreta"),
        "Ljava/security/MessageDigest;->getInstance": ("Crypto", "INFO", "Uso de hash criptográfico"),
        "Ljava/net/URL;->openConnection": ("Network", "MEDIO", "Conexión de red directa"),
        "Ljava/net/HttpURLConnection;->": ("Network", "MEDIO", "Conexión HTTP directa"),
        "Landroid/telephony/TelephonyManager;->getDeviceId": ("Privacy", "ALTO", "Lectura de IMEI"),
        "Landroid/telephony/TelephonyManager;->getLine1Number": ("Privacy", "ALTO", "Lectura del número telefónico"),
        "Landroid/telephony/TelephonyManager;->getSubscriberId": ("Privacy", "ALTO", "Lectura de IMSI"),
        "Landroid/telephony/TelephonyManager;->getSimSerialNumber": ("Privacy", "ALTO", "Lectura serial SIM"),
        "Landroid/location/LocationManager;->getLastKnownLocation": ("Privacy", "ALTO", "Obtener última ubicación"),
        "Landroid/location/LocationManager;->requestLocationUpdates": ("Privacy", "ALTO", "Rastreo de ubicación continuo"),
        "Landroid/content/pm/PackageManager;->getInstalledPackages": ("Recon", "MEDIO", "Enumerar apps instaladas"),
        "Landroid/content/pm/PackageManager;->getInstalledApplications": ("Recon", "MEDIO", "Enumerar aplicaciones"),
        "Landroid/hardware/Camera;->open": ("Privacy", "ALTO", "Acceso a cámara"),
        "Landroid/media/MediaRecorder;->setAudioSource": ("Privacy", "CRITICO", "Grabación de audio"),
        "Landroid/media/AudioRecord;->": ("Privacy", "CRITICO", "Grabación de audio directa"),
        "Landroid/app/NotificationManager;->cancel": ("Evasion", "MEDIO", "Cancelar notificaciones"),
        "Landroid/content/ContentResolver;->query": ("Data", "MEDIO", "Consulta de ContentProvider"),
        "Landroid/content/ContentResolver;->delete": ("Data", "ALTO", "Eliminación vía ContentProvider"),
        "Landroid/content/ContentResolver;->insert": ("Data", "MEDIO", "Inserción vía ContentProvider"),
        "Ljava/lang/Class;->forName": ("Dynamic", "MEDIO", "Carga dinámica de clase"),
        "Ljava/lang/Class;->getMethod": ("Dynamic", "MEDIO", "Obtención dinámica de método"),
        "Ljava/lang/reflect/Method;->invoke": ("Dynamic", "ALTO", "Invocación por reflexión"),
        "Landroid/os/Build;->": ("Fingerprint", "INFO", "Lectura info del dispositivo"),
        "Landroid/provider/Settings$Secure;->getString": ("Fingerprint", "MEDIO", "Lectura de Android ID"),
    }

    @staticmethod
    def analyze(apk_path):
        if not HAS_ANDROGUARD:
            return {"available": False, "error": "Androguard no instalado (pip install androguard)"}

        result = {
            "available": True,
            "package": "", "app_name": "", "version_name": "", "version_code": "",
            "min_sdk": "", "target_sdk": "", "max_sdk": "",
            "permissions": [], "activities": [], "services": [], "receivers": [], "providers": [],
            "main_activity": "", "is_signed": False, "is_valid_apk": False,
            "dex_stats": {},
            "dangerous_api_calls": [],
            "api_by_category": {},
            "interesting_strings": [],
            "class_count": 0, "method_count": 0,
            "libraries_detected": [],
        }

        try:
            apk = APK(apk_path)
            result["is_valid_apk"] = apk.is_valid_APK()
            result["package"] = apk.get_package()
            result["app_name"] = apk.get_app_name()
            result["version_name"] = apk.get_androidversion_name()
            result["version_code"] = apk.get_androidversion_code()
            result["min_sdk"] = apk.get_min_sdk_version() or ""
            result["target_sdk"] = apk.get_target_sdk_version() or ""
            result["max_sdk"] = apk.get_max_sdk_version() or ""
            result["permissions"] = apk.get_permissions()
            result["activities"] = apk.get_activities()
            result["services"] = apk.get_services()
            result["receivers"] = apk.get_receivers()
            result["providers"] = apk.get_providers()
            result["main_activity"] = apk.get_main_activity() or ""
            result["is_signed"] = apk.is_signed()
            result["libraries_detected"] = list(apk.get_libraries())

        except Exception as e:
            result["apk_error"] = str(e)

        # Análisis DEX profundo
        try:
            apk_obj, dalvik_list, analysis = AnalyzeAPK(apk_path)

            total_classes = 0
            total_methods = 0
            api_calls = []
            api_by_cat = defaultdict(list)
            interesting_strings = set()

            for dex in dalvik_list:
                classes = dex.get_classes()
                total_classes += len(classes)

                for cls in classes:
                    for method in cls.get_methods():
                        total_methods += 1

                # Buscar strings interesantes en el DEX
                for s in dex.get_strings():
                    s_str = str(s)
                    # URLs, IPs, paths sospechosos
                    if any(pat in s_str.lower() for pat in [
                        'http://', 'https://', 'ftp://', '/system/', '/data/',
                        'su', 'root', 'admin', 'password', 'secret', 'token',
                        'api_key', 'apikey', '.onion', 'base64',
                    ]):
                        if len(s_str) > 6 and len(s_str) < 500:
                            interesting_strings.add(s_str)

            # Buscar llamadas a APIs peligrosas via el análisis
            if analysis:
                for api_sig, (category, severity, desc) in AndroguardAnalyzer.DANGEROUS_APIS.items():
                    # Buscar en las external classes
                    parts = api_sig.rsplit(";->", 1)
                    if len(parts) == 2:
                        cls_name = parts[0] + ";"
                        method_name = parts[1]
                        try:
                            methods = analysis.find_methods(classname=cls_name.replace("L","").replace(";","").replace("/","."),
                                                            methodname=method_name if method_name else ".*")
                            found_count = 0
                            for m in methods:
                                found_count += 1
                                if found_count > 0:
                                    break

                            if found_count > 0:
                                entry = {
                                    "api": api_sig, "category": category,
                                    "severity": severity, "description": desc,
                                }
                                api_calls.append(entry)
                                api_by_cat[category].append(entry)
                        except Exception as e:
                            logger.debug(f"Androguard: error buscando API {api_sig}: {e}")

            result["class_count"] = total_classes
            result["method_count"] = total_methods
            result["dangerous_api_calls"] = api_calls
            result["api_by_category"] = dict(api_by_cat)
            result["interesting_strings"] = sorted(list(interesting_strings))[:200]

            result["dex_stats"] = {
                "total_classes": total_classes,
                "total_methods": total_methods,
                "dangerous_apis_found": len(api_calls),
                "interesting_strings_count": len(interesting_strings),
            }

        except Exception as e:
            result["dex_error"] = str(e)

        return result


# ====================================================================
# MODULO 8C: QUARK-ENGINE - DETECCION HEURISTICA DE MALWARE
# ====================================================================

class QuarkAnalyzer:
    """Motor heurístico Quark-Engine para clasificación de comportamiento malicioso.

    Usa API de bajo nivel (QuarkCore + RuleObject) cuando está disponible para
    cargar el APK una sola vez e iterar las reglas sobre el mismo objeto (~10-30× más rápido).
    Fallback automático a QuarkReport si la versión no soporta la API moderna.
    """

    RULES_DIR = os.path.expanduser("~/.quark-engine/quark-rules")
    MAX_APK_SIZE_MB = 150

    @staticmethod
    def _classify_behavior(crime_desc, entry, behaviors):
        """Clasifica una regla coincidente en categoría de comportamiento."""
        crime_lower = crime_desc.lower()
        if any(w in crime_lower for w in ['sms', 'message', 'text message']):
            behaviors["SMS Abuse"].append(entry)
        elif any(w in crime_lower for w in ['location', 'gps', 'coordinate']):
            behaviors["Location Tracking"].append(entry)
        elif any(w in crime_lower for w in ['camera', 'photo', 'picture', 'record']):
            behaviors["Surveillance"].append(entry)
        elif any(w in crime_lower for w in ['contact', 'phone', 'call']):
            behaviors["Contact/Call Abuse"].append(entry)
        elif any(w in crime_lower for w in ['file', 'read', 'write', 'storage', 'download']):
            behaviors["File Operations"].append(entry)
        elif any(w in crime_lower for w in ['network', 'http', 'url', 'connect', 'send']):
            behaviors["Network Activity"].append(entry)
        elif any(w in crime_lower for w in ['install', 'package', 'execute', 'command']):
            behaviors["Code Execution"].append(entry)
        elif any(w in crime_lower for w in ['encrypt', 'cipher', 'crypto', 'ransom']):
            behaviors["Cryptographic Ops"].append(entry)
        elif any(w in crime_lower for w in ['hide', 'stealth', 'delete', 'remove log']):
            behaviors["Evasion/Stealth"].append(entry)
        elif any(w in crime_lower for w in ['device', 'imei', 'serial', 'id']):
            behaviors["Device Fingerprinting"].append(entry)
        else:
            behaviors["Other"].append(entry)

    @staticmethod
    def _analyze_lowlevel(apk_path, rule_files):
        """Ruta de bajo nivel: carga el APK una sola vez, itera reglas."""
        matched_rules = []
        total_score = 0
        max_possible = 0
        behaviors = defaultdict(list)
        rules_scanned = 0

        quark = QuarkCore(apk_path)

        for idx, rule_path in enumerate(rule_files):
            try:
                rule_obj = RuleObject(rule_path)
                quark.run(rule_obj)

                crime_desc = rule_obj.crime if hasattr(rule_obj, 'crime') else "Unknown"
                rule_score = quark.quark_analysis.score_mapping.get(rule_path, 0) if hasattr(quark, 'quark_analysis') else 0

                # Intentar obtener score de report si el método anterior falla
                if rule_score == 0:
                    try:
                        rule_score = rule_obj.score if hasattr(rule_obj, 'score') else 0
                    except Exception:
                        pass

                max_possible += 100
                rules_scanned += 1

                if rule_score > 0:
                    total_score += rule_score
                    confidence_map = {20: "20%", 40: "40%", 60: "60%", 80: "80%", 100: "100%"}
                    confidence = confidence_map.get(rule_score, f"{rule_score}%")

                    entry = {
                        "rule": os.path.basename(rule_path),
                        "crime": crime_desc,
                        "score": rule_score,
                        "confidence": confidence,
                    }
                    matched_rules.append(entry)
                    QuarkAnalyzer._classify_behavior(crime_desc, entry, behaviors)

            except Exception as e:
                logger.debug(f"Quark low-level: error en regla {rule_path}: {e}")
                continue
            finally:
                if (idx + 1) % 10 == 0:
                    gc.collect()

        # Limpiar el objeto Quark
        del quark
        gc.collect()

        return matched_rules, total_score, max_possible, behaviors, rules_scanned

    @staticmethod
    def _analyze_highlevel(apk_path, rule_files):
        """Ruta legacy: QuarkReport (parsea el APK en cada regla)."""
        matched_rules = []
        total_score = 0
        max_possible = 0
        behaviors = defaultdict(list)
        rules_scanned = 0

        for idx, rule_path in enumerate(rule_files):
            try:
                report = QuarkReport()
                report.analysis(apk_path, rule_path)

                with open(rule_path, 'r') as rf:
                    rule_json = json.load(rf)
                crime_desc = rule_json.get("crime", "Unknown")
                rule_score = report.get_score()
                max_possible += 100

                rules_scanned += 1

                if rule_score > 0:
                    total_score += rule_score
                    confidence = report.get_confidence()

                    entry = {
                        "rule": os.path.basename(rule_path),
                        "crime": crime_desc,
                        "score": rule_score,
                        "confidence": confidence,
                    }
                    matched_rules.append(entry)
                    QuarkAnalyzer._classify_behavior(crime_desc, entry, behaviors)

            except Exception as e:
                logger.debug(f"Quark high-level: error en regla {rule_path}: {e}")
                continue
            finally:
                try:
                    del report
                except NameError:
                    pass
                if (idx + 1) % 5 == 0:
                    gc.collect()

        return matched_rules, total_score, max_possible, behaviors, rules_scanned

    @staticmethod
    def analyze(apk_path, max_rules=0):
        if not HAS_QUARK:
            return {"available": False, "error": "Quark-Engine no instalado (pip install quark-engine)"}

        # Pre-check: tamaño del APK
        try:
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
            if apk_size_mb > QuarkAnalyzer.MAX_APK_SIZE_MB:
                logger.warning(f"Quark: APK demasiado grande ({apk_size_mb:.0f} MB > "
                               f"{QuarkAnalyzer.MAX_APK_SIZE_MB} MB) - omitiendo análisis")
                return {
                    "available": False,
                    "error": f"APK demasiado grande ({apk_size_mb:.0f} MB) para análisis Quark. "
                             f"Límite: {QuarkAnalyzer.MAX_APK_SIZE_MB} MB"
                }
        except OSError:
            pass

        result = {
            "available": True,
            "threat_level": "",
            "total_score": 0,
            "max_score": 0,
            "rules_matched": [],
            "rules_scanned": 0,
            "behaviors_detected": [],
            "classification": {},
            "summary": "",
            "api_used": "low-level" if HAS_QUARK_LOWLEVEL else "high-level",
        }

        rules_dir = QuarkAnalyzer.RULES_DIR
        if not os.path.isdir(rules_dir):
            try:
                from quark.freshquark import download
                download()
            except ImportError:
                logger.warning("quark.freshquark no disponible - descarga de reglas no soportada")
                result["error"] = "Directorio de reglas Quark no encontrado y freshquark no disponible"
                return result
            except Exception as e:
                result["error"] = f"No se pudieron descargar reglas: {e}"
                return result

        rule_files = sorted([
            os.path.join(rules_dir, f) for f in os.listdir(rules_dir)
            if f.endswith('.json')
        ])

        if max_rules > 0:
            rule_files = rule_files[:max_rules]

        if not rule_files:
            result["error"] = "No se encontraron reglas de Quark"
            return result

        # Elegir ruta de análisis
        if HAS_QUARK_LOWLEVEL:
            logger.info(f"Quark: usando API low-level (carga APK una sola vez) para {len(rule_files)} reglas")
            try:
                matched_rules, total_score, max_possible, behaviors, rules_scanned = \
                    QuarkAnalyzer._analyze_lowlevel(apk_path, rule_files)
            except Exception as e:
                logger.warning(f"Quark low-level falló ({e}), cayendo a high-level")
                result["api_used"] = "high-level (fallback)"
                matched_rules, total_score, max_possible, behaviors, rules_scanned = \
                    QuarkAnalyzer._analyze_highlevel(apk_path, rule_files)
        else:
            logger.info(f"Quark: usando API high-level (legacy) para {len(rule_files)} reglas")
            matched_rules, total_score, max_possible, behaviors, rules_scanned = \
                QuarkAnalyzer._analyze_highlevel(apk_path, rule_files)

        # Ordenar por score
        matched_rules.sort(key=lambda x: x["score"], reverse=True)

        result["rules_matched"] = matched_rules
        result["total_score"] = total_score
        result["max_score"] = max_possible
        result["rules_scanned"] = rules_scanned
        result["behaviors_detected"] = [
            {"behavior": k, "count": len(v), "rules": v}
            for k, v in sorted(behaviors.items(), key=lambda x: len(x[1]), reverse=True)
        ]

        # Clasificación de amenaza
        if max_possible > 0:
            threat_pct = (total_score / max_possible) * 100
        else:
            threat_pct = 0

        if threat_pct >= 30:
            result["threat_level"] = "CRITICO"
            result["classification"] = {"label": "Probable Malware", "confidence": "Alta"}
        elif threat_pct >= 15:
            result["threat_level"] = "ALTO"
            result["classification"] = {"label": "Comportamiento Sospechoso", "confidence": "Media-Alta"}
        elif threat_pct >= 5:
            result["threat_level"] = "MEDIO"
            result["classification"] = {"label": "Actividad Cuestionable", "confidence": "Media"}
        elif threat_pct > 0:
            result["threat_level"] = "BAJO"
            result["classification"] = {"label": "Riesgo Menor", "confidence": "Baja"}
        else:
            result["threat_level"] = "LIMPIO"
            result["classification"] = {"label": "Sin Comportamiento Malicioso Detectado", "confidence": "Alta"}

        result["summary"] = (
            f"Quark escaneó {rules_scanned} reglas ({result['api_used']}), "
            f"{len(matched_rules)} coincidieron. "
            f"Nivel de amenaza: {result['threat_level']}. "
            f"Comportamientos detectados: {', '.join(b['behavior'] for b in result['behaviors_detected'][:5]) or 'Ninguno'}"
        )

        return result


# ====================================================================
# MODULO 8D: ENJARIFY - CONVERSION DEX A JAR
# ====================================================================

class EnjarifyConverter:
    """Convierte DEX a JAR para análisis complementario.
    Usa enjarify si está disponible, o dex2jar como fallback."""

    @staticmethod
    def convert(apk_path, output_dir):
        result = {
            "available": False,
            "jar_path": None,
            "method": None,
            "jar_contents": {},
            "class_count": 0,
            "package_structure": [],
        }

        jar_path = os.path.join(output_dir, "converted.jar")

        # Intentar enjarify (Python puro, si está clonado localmente)
        enjarify_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enjarify_tool", "enjarify.py")
        if os.path.exists(enjarify_script):
            try:
                proc = subprocess.run(
                    [sys.executable, enjarify_script, "-o", jar_path, apk_path],
                    capture_output=True, text=True, timeout=120)
                if os.path.exists(jar_path):
                    result["available"] = True
                    result["jar_path"] = jar_path
                    result["method"] = "enjarify"
            except Exception:
                pass

        # Fallback: enjarify en PATH
        if not result["available"]:
            for cmd in ["enjarify", "enjarify.sh"]:
                try:
                    proc = subprocess.run(
                        [cmd, "-o", jar_path, apk_path],
                        capture_output=True, text=True, timeout=120)
                    if os.path.exists(jar_path):
                        result["available"] = True
                        result["jar_path"] = jar_path
                        result["method"] = "enjarify"
                        break
                except FileNotFoundError:
                    continue

        # Fallback: d2j-dex2jar
        if not result["available"]:
            for cmd in ["d2j-dex2jar", "dex2jar", "d2j-dex2jar.sh"]:
                try:
                    proc = subprocess.run(
                        [cmd, "-o", jar_path, "-f", apk_path],
                        capture_output=True, text=True, timeout=120)
                    if os.path.exists(jar_path):
                        result["available"] = True
                        result["jar_path"] = jar_path
                        result["method"] = "dex2jar"
                        break
                except FileNotFoundError:
                    continue

        # Si se generó el JAR, analizarlo
        if result["available"] and result["jar_path"] and os.path.exists(result["jar_path"]):
            try:
                with zipfile.ZipFile(result["jar_path"], 'r') as jf:
                    entries = jf.namelist()
                    classes = [e for e in entries if e.endswith('.class')]
                    result["class_count"] = len(classes)

                    # Extraer estructura de paquetes
                    packages = set()
                    for cls in classes:
                        parts = cls.rsplit('/', 1)
                        if len(parts) > 1:
                            packages.add(parts[0].replace('/', '.'))
                    result["package_structure"] = sorted(list(packages))[:100]

                    # Estadísticas por tipo de archivo
                    by_ext = defaultdict(int)
                    for e in entries:
                        ext = Path(e).suffix.lower() or "(sin ext)"
                        by_ext[ext] += 1
                    result["jar_contents"] = dict(by_ext)

            except Exception as e:
                result["jar_error"] = str(e)
        else:
            result["note"] = "Ni enjarify ni dex2jar están disponibles. Instale enjarify (Google) o dex-tools para esta funcionalidad."

        return result


# ====================================================================
# MODULO 8E: YARA - MOTOR DE REGLAS Y FIRMAS
# ====================================================================

class YaraScanner:
    """Escaneo de APK con reglas YARA para detección de malware y clasificación."""

    DEFAULT_RULES_DIRS = [
        os.path.expanduser("~/.apkilis/yara-rules"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "android"),
        "/usr/share/yara-rules",
    ]

    BUILTIN_RULES_SRC = """
rule Packer_Jiagu {
    meta:
        description = "Detecta packer Qihoo 360 Jiagu"
        category = "packer"
        severity = "ALTO"
    strings:
        $a = "libjiagu" ascii wide
        $b = "com.qihoo.util" ascii
        $c = "libjiagu_art" ascii
    condition:
        any of them
}

rule Packer_Bangcle {
    meta:
        description = "Detecta packer Bangcle/SecNeo"
        category = "packer"
        severity = "ALTO"
    strings:
        $a = "libsecexe" ascii wide
        $b = "libsecmain" ascii wide
        $c = "bangcleplugin" ascii
    condition:
        any of them
}

rule Packer_DexGuard {
    meta:
        description = "Detecta ofuscador DexGuard"
        category = "obfuscator"
        severity = "MEDIO"
    strings:
        $a = "DexGuard" ascii wide
        $b = "dexguard" ascii
        $c = "com.guardsquare" ascii
    condition:
        any of them
}

rule Packer_DexProtector {
    meta:
        description = "Detecta DexProtector"
        category = "packer"
        severity = "ALTO"
    strings:
        $a = "DexProtector" ascii wide
        $b = "dexprotector" ascii
    condition:
        any of them
}

rule Malware_Joker {
    meta:
        description = "Indicadores de familia Joker (fraude SMS)"
        category = "malware_family"
        severity = "CRITICO"
    strings:
        $a = "Ljjjjje/bbbbb/" ascii
        $b = "eajadihgfc" ascii
        $c = "WapBillingService" ascii
        $d = "loadPaymentData" ascii
        $e = "getCarrierBillingInfo" ascii
    condition:
        2 of them
}

rule Malware_BankBot {
    meta:
        description = "Indicadores de troyano bancario"
        category = "malware_family"
        severity = "CRITICO"
    strings:
        $a = "inject" ascii
        $b = "overlay" ascii
        $c = "grabber" ascii
        $d = "keylog" ascii
        $e = "admin_lock" ascii
        $f = "sms_intercept" ascii
    condition:
        3 of them
}

rule Suspicious_RootExploit {
    meta:
        description = "Herramientas de root/exploit"
        category = "rootkit"
        severity = "CRITICO"
    strings:
        $a = "/system/bin/su" ascii
        $b = "Superuser.apk" ascii
        $c = "daemonsu" ascii
        $d = "/.magisk" ascii
        $e = "ro.debuggable" ascii
        $f = "CVE-20" ascii
    condition:
        3 of them
}

rule CryptoMiner {
    meta:
        description = "Indicadores de minero de criptomonedas"
        category = "cryptominer"
        severity = "CRITICO"
    strings:
        $a = "stratum+tcp://" ascii wide
        $b = "coinhive" ascii wide nocase
        $c = "cryptonight" ascii wide nocase
        $d = "hashrate" ascii wide nocase
        $e = "xmrig" ascii wide nocase
        $f = "monero" ascii wide nocase
    condition:
        2 of them
}

rule Adware_Aggressive {
    meta:
        description = "Adware agresivo con tecnicas de persistencia"
        category = "adware"
        severity = "ALTO"
    strings:
        $a = "loadInterstitialAd" ascii
        $b = "BOOT_COMPLETED" ascii
        $c = "showAd" ascii
        $d = "forceOpen" ascii
        $e = "lockScreen" ascii
    condition:
        3 of them
}

rule Spyware_Indicators {
    meta:
        description = "Indicadores de spyware comercial"
        category = "spyware"
        severity = "CRITICO"
    strings:
        $a = "getCallLog" ascii
        $b = "getSmsInbox" ascii
        $c = "getLocation" ascii
        $d = "recordAudio" ascii
        $e = "takeScreenshot" ascii
        $f = "uploadData" ascii
        $g = "hideApp" ascii
    condition:
        3 of them
}
"""

    @staticmethod
    def scan(apk_path, decompiled_dir=None):
        if not HAS_YARA:
            return {"available": False, "error": "yara-python no instalado (pip install yara-python)"}

        result = {
            "available": True,
            "matches": [],
            "by_category": {},
            "rules_loaded": 0,
            "files_scanned": 0,
            "summary": "",
        }

        compiled_rules = []

        # Compilar reglas builtin
        try:
            builtin = yara.compile(source=YaraScanner.BUILTIN_RULES_SRC)
            compiled_rules.append(("builtin", builtin))
        except Exception as e:
            result["builtin_error"] = str(e)

        # Cargar reglas externas de directorios (recursivo, con filtro Android)
        MAX_EXTERNAL_RULES = 200  # Limite para evitar lentitud
        external_loaded = 0
        for rules_dir in YaraScanner.DEFAULT_RULES_DIRS:
            if not os.path.isdir(rules_dir):
                continue
            for root, _, fnames in os.walk(rules_dir):
                if external_loaded >= MAX_EXTERNAL_RULES:
                    break
                for fname in fnames:
                    if external_loaded >= MAX_EXTERNAL_RULES:
                        break
                    if not fname.endswith(('.yar', '.yara', '.rul')):
                        continue
                    try:
                        rule = yara.compile(filepath=os.path.join(root, fname))
                        compiled_rules.append((fname, rule))
                        external_loaded += 1
                    except Exception:
                        continue

        result["rules_loaded"] = len(compiled_rules)

        # Archivos a escanear
        scan_targets = [apk_path]
        if decompiled_dir and os.path.isdir(decompiled_dir):
            for root, _, files in os.walk(decompiled_dir):
                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in ('.dex', '.so', '.jar', '.bin', '.dat', '.elf'):
                        scan_targets.append(os.path.join(root, f))

        # También escanear .so y .dex dentro del APK
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                tmpdir = tempfile.mkdtemp(prefix="apkilis_yara_")
                for info in zf.infolist():
                    if info.filename.endswith(('.dex', '.so')):
                        extracted = zf.extract(info, tmpdir)
                        scan_targets.append(extracted)
        except Exception as e:
            logger.warning(f"YARA: Error extrayendo archivos del APK: {e}")

        all_matches = []
        by_cat = defaultdict(list)

        for target in scan_targets:
            if not os.path.isfile(target):
                continue
            result["files_scanned"] += 1
            for rule_name, compiled in compiled_rules:
                try:
                    matches = compiled.match(target, timeout=30)
                    for m in matches:
                        meta = m.meta if hasattr(m, 'meta') else {}
                        entry = {
                            "rule": m.rule,
                            "source": rule_name,
                            "file": os.path.basename(target),
                            "tags": list(m.tags) if hasattr(m, 'tags') else [],
                            "category": meta.get("category", "unknown"),
                            "severity": meta.get("severity", "MEDIO"),
                            "description": meta.get("description", m.rule),
                            "strings_matched": len(m.strings) if hasattr(m, 'strings') else 0,
                        }
                        all_matches.append(entry)
                        by_cat[entry["category"]].append(entry)
                except Exception:
                    continue

        # Limpiar tmpdir
        if tmpdir and os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

        # Deduplicar por nombre de regla
        seen = set()
        unique = []
        for m in all_matches:
            key = m["rule"]
            if key not in seen:
                seen.add(key)
                unique.append(m)

        result["matches"] = unique
        result["by_category"] = {k: v for k, v in by_cat.items()}
        result["summary"] = (
            f"YARA: {result['rules_loaded']} reglas cargadas, "
            f"{result['files_scanned']} archivos escaneados, "
            f"{len(unique)} coincidencias únicas"
        )

        return result


# ====================================================================
# MODULO 8F: APKiD - DETECCION DE PACKERS/OFUSCADORES/PROTECTORES
# ====================================================================

class APKiDAnalyzer:
    """Detecta packers, ofuscadores y protectores usando APKiD (subprocess)."""

    @staticmethod
    def analyze(apk_path):
        result = {
            "available": False,
            "detections": [],
            "packers": [],
            "obfuscators": [],
            "protectors": [],
            "compilers": [],
            "anti_analysis": [],
            "summary": "",
        }

        # Intentar ejecutar apkid
        for cmd in ["apkid", "APKiD"]:
            try:
                proc = subprocess.run(
                    [cmd, "-j", apk_path],
                    capture_output=True, text=True, timeout=120)
                if proc.returncode == 0 and proc.stdout.strip():
                    result["available"] = True
                    try:
                        data = json.loads(proc.stdout)
                        APKiDAnalyzer._parse_output(data, result)
                    except json.JSONDecodeError:
                        APKiDAnalyzer._parse_text_output(proc.stdout, result)
                    break
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                result["error"] = "APKiD timeout (>120s)"
                return result
            except Exception as e:
                result["error"] = str(e)

        if not result["available"]:
            # Intentar como módulo Python
            try:
                from apkid.apkid import Scanner, Options
                from apkid.output import OutputFormatter
                from apkid.rules import RulesManager
                options = Options(json_output=True, timeout=60, recursive=True)
                rules = RulesManager()
                rules.load()
                scanner = Scanner(rules, options)
                res = scanner.scan_file(apk_path)
                result["available"] = True
                APKiDAnalyzer._parse_scanner_result(res, result)
            except ImportError:
                result["error"] = "APKiD no instalado (pip install apkid)"
            except Exception as e:
                result["error"] = f"APKiD error: {e}"

        if not result["available"]:
            return result

        result["summary"] = (
            f"APKiD: {len(result['packers'])} packers, "
            f"{len(result['obfuscators'])} ofuscadores, "
            f"{len(result['protectors'])} protectores, "
            f"{len(result['anti_analysis'])} anti-análisis"
        )

        return result

    @staticmethod
    def _parse_output(data, result):
        files = data.get("files", []) if isinstance(data, dict) else data if isinstance(data, list) else []
        if isinstance(data, dict) and not files:
            files = [{"matches": data}]

        for fdata in files:
            matches = fdata if isinstance(fdata, dict) else {}
            for fname, detections in matches.items():
                if fname in ("files", "filename"):
                    continue
                if isinstance(detections, dict):
                    for det_type, det_list in detections.items():
                        items = det_list if isinstance(det_list, list) else [det_list]
                        for item in items:
                            entry = {"type": det_type, "value": str(item), "file": str(fname)}
                            result["detections"].append(entry)
                            APKiDAnalyzer._classify(entry, result)

    @staticmethod
    def _parse_text_output(text, result):
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('['):
                continue
            for keyword in ['packer', 'obfuscator', 'protector', 'compiler', 'anti']:
                if keyword in line.lower():
                    entry = {"type": keyword, "value": line, "file": ""}
                    result["detections"].append(entry)
                    APKiDAnalyzer._classify(entry, result)
                    break

    @staticmethod
    def _parse_scanner_result(res, result):
        if hasattr(res, 'results'):
            for item in res.results:
                entry = {"type": getattr(item, 'type', 'unknown'),
                         "value": getattr(item, 'value', str(item)),
                         "file": getattr(item, 'filename', '')}
                result["detections"].append(entry)
                APKiDAnalyzer._classify(entry, result)

    @staticmethod
    def _classify(entry, result):
        t = entry.get("type", "").lower()
        v = entry.get("value", "").lower()
        combined = f"{t} {v}"
        if any(w in combined for w in ['pack', 'jiagu', 'bangcle', 'secneo', 'ijiami']):
            result["packers"].append(entry)
        elif any(w in combined for w in ['obfuscat', 'proguard', 'allatori', 'dasho', 'dexguard']):
            result["obfuscators"].append(entry)
        elif any(w in combined for w in ['protect', 'dexprotect', 'arxan', 'medusa']):
            result["protectors"].append(entry)
        elif any(w in combined for w in ['anti', 'debug', 'emulator', 'tamper', 'frida', 'xposed']):
            result["anti_analysis"].append(entry)
        elif any(w in combined for w in ['compil', 'dx', 'd8', 'r8', 'jack']):
            result["compilers"].append(entry)


# ====================================================================
# MODULO 8G: LIEF - ANALISIS DE LIBRERIAS NATIVAS ELF (.so)
# ====================================================================

class LIEFAnalyzer:
    """Análisis profundo de librerías nativas .so usando LIEF."""

    DANGEROUS_IMPORTS = {
        "system": ("CRITICO", "Ejecución de comandos del sistema"),
        "exec": ("CRITICO", "Ejecución de procesos"),
        "execve": ("CRITICO", "Ejecución de procesos (execve)"),
        "execvp": ("CRITICO", "Ejecución de procesos (execvp)"),
        "popen": ("CRITICO", "Ejecución con pipe"),
        "fork": ("ALTO", "Creación de proceso hijo"),
        "ptrace": ("ALTO", "Depuración/anti-depuración de procesos"),
        "dlopen": ("ALTO", "Carga dinámica de librería"),
        "dlsym": ("ALTO", "Resolución dinámica de símbolos"),
        "socket": ("MEDIO", "Comunicación de red a bajo nivel"),
        "connect": ("MEDIO", "Conexión de red"),
        "send": ("MEDIO", "Envío de datos por red"),
        "recv": ("MEDIO", "Recepción de datos por red"),
        "sendto": ("MEDIO", "Envío de datos UDP"),
        "recvfrom": ("MEDIO", "Recepción de datos UDP"),
        "open": ("BAJO", "Apertura de archivos"),
        "write": ("BAJO", "Escritura de archivos"),
        "read": ("BAJO", "Lectura de archivos"),
        "mmap": ("MEDIO", "Mapeo de memoria"),
        "mprotect": ("ALTO", "Cambio de protección de memoria (posible ROP/JIT)"),
        "unlink": ("MEDIO", "Eliminación de archivos"),
        "chmod": ("MEDIO", "Cambio de permisos de archivos"),
        "chown": ("MEDIO", "Cambio de propietario de archivos"),
        "kill": ("MEDIO", "Envío de señales a procesos"),
        "getpid": ("BAJO", "Obtener PID del proceso"),
        "__system_property_get": ("MEDIO", "Lectura de propiedades del sistema Android"),
        "JNI_OnLoad": ("INFO", "Punto de entrada JNI"),
    }

    @staticmethod
    def analyze(apk_path):
        if not HAS_LIEF:
            return {"available": False, "error": "LIEF no instalado (pip install lief)"}

        result = {
            "available": True,
            "libraries": [],
            "total_libs": 0,
            "dangerous_imports_found": [],
            "suspicious_libs": [],
            "has_debug_symbols": False,
            "architectures_detail": {},
            "summary": "",
        }

        tmpdir = tempfile.mkdtemp(prefix="apkilis_lief_")

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                so_files = [f for f in zf.namelist() if f.endswith('.so')]
                result["total_libs"] = len(so_files)

                for so_name in so_files:
                    try:
                        extracted = zf.extract(so_name, tmpdir)
                        lib_info = LIEFAnalyzer._analyze_single_so(extracted, so_name)
                        result["libraries"].append(lib_info)

                        # Recopilar imports peligrosos
                        for imp in lib_info.get("dangerous_imports", []):
                            imp["library"] = so_name
                            result["dangerous_imports_found"].append(imp)

                        # Detectar libs sospechosas
                        basename = os.path.basename(so_name).lower()
                        suspicious_names = ['hack', 'inject', 'hook', 'xposed', 'frida',
                                            'substrate', 'cydia', 'hide', 'root', 'exploit']
                        if any(s in basename for s in suspicious_names):
                            result["suspicious_libs"].append({
                                "path": so_name, "reason": "Nombre sospechoso"})

                        if lib_info.get("has_debug"):
                            result["has_debug_symbols"] = True

                        # Arquitectura
                        arch = lib_info.get("arch", "unknown")
                        if arch not in result["architectures_detail"]:
                            result["architectures_detail"][arch] = {"count": 0, "libs": []}
                        result["architectures_detail"][arch]["count"] += 1
                        result["architectures_detail"][arch]["libs"].append(os.path.basename(so_name))

                    except Exception as e:
                        logger.debug(f"LIEF: error analizando {so_name}: {e}")
                        continue

        except Exception as e:
            result["error"] = str(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        criticos = [i for i in result["dangerous_imports_found"] if i.get("severity") == "CRITICO"]
        result["summary"] = (
            f"LIEF: {result['total_libs']} libs nativas, "
            f"{len(result['dangerous_imports_found'])} imports peligrosos "
            f"({len(criticos)} críticos), "
            f"{len(result['suspicious_libs'])} libs sospechosas"
        )

        return result

    @staticmethod
    def _analyze_single_so(filepath, original_path):
        info = {
            "path": original_path,
            "name": os.path.basename(original_path),
            "arch": "unknown",
            "bits": 0,
            "has_debug": False,
            "is_stripped": True,
            "imported_functions": [],
            "exported_functions": [],
            "dangerous_imports": [],
            "imported_libraries": [],
            "sections": [],
            "size": os.path.getsize(filepath),
        }

        try:
            binary = lief.parse(filepath)
            if binary is None:
                return info

            # Arquitectura
            if hasattr(binary, 'header'):
                machine = binary.header.machine_type
                info["arch"] = str(machine).split('.')[-1] if machine else "unknown"
                info["bits"] = 64 if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else 32

            # Funciones importadas
            if hasattr(binary, 'imported_functions'):
                for func in binary.imported_functions:
                    fname = func.name if hasattr(func, 'name') else str(func)
                    info["imported_functions"].append(fname)
                    if fname in LIEFAnalyzer.DANGEROUS_IMPORTS:
                        sev, desc = LIEFAnalyzer.DANGEROUS_IMPORTS[fname]
                        info["dangerous_imports"].append({
                            "function": fname, "severity": sev, "description": desc})

            # Funciones exportadas
            if hasattr(binary, 'exported_functions'):
                for func in binary.exported_functions:
                    fname = func.name if hasattr(func, 'name') else str(func)
                    info["exported_functions"].append(fname)

            # Librerías importadas
            if hasattr(binary, 'libraries'):
                info["imported_libraries"] = list(binary.libraries)

            # Secciones
            if hasattr(binary, 'sections'):
                for section in binary.sections:
                    sec_info = {
                        "name": section.name,
                        "size": section.size,
                        "entropy": round(section.entropy, 2) if hasattr(section, 'entropy') else 0,
                    }
                    info["sections"].append(sec_info)
                    if section.name == ".debug_info":
                        info["has_debug"] = True
                        info["is_stripped"] = False

            # Alta entropía en secciones = posible empaquetado
            for sec in info["sections"]:
                if sec["entropy"] > 7.0 and sec["size"] > 1024:
                    info.setdefault("high_entropy_sections", []).append(sec)

        except Exception as e:
            info["parse_error"] = str(e)

        return info


# ====================================================================
# MODULO 8H: ENDPOINT EXTRACTOR - URLS, APIs, DOMINIOS, CLOUD
# ====================================================================

class EndpointExtractor:
    """Extraccion offline de URLs, APIs, dominios, recursos cloud y deep links."""

    # Dominios de SDK/Android que generan ruido
    NOISE_DOMAINS = {
        "schemas.android.com", "www.w3.org", "ns.adobe.com",
        "googleapis.com", "www.googleapis.com", "google.com",
        "www.google.com", "gstatic.com", "www.gstatic.com",
        "android.com", "developer.android.com", "play.google.com",
        "dl.google.com", "fonts.googleapis.com", "maps.googleapis.com",
        "xmlpull.org", "apache.org", "www.apache.org",
        "json.org", "www.json.org", "xmlns.com",
        "purl.org", "ogp.me", "schema.org",
    }

    # Patrones compilados
    RE_URL = re.compile(r'https?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.ASCII)
    RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    RE_API_PATH = re.compile(r'["\'](/(?:api|v[1-9]|rest|graphql|oauth|auth|login|token|webhook|callback|ws)[/\w.\-]*)["\']', re.IGNORECASE)
    RE_S3 = re.compile(r'[\w.\-]+\.s3[\w.\-]*\.amazonaws\.com|s3[\w.\-]*\.amazonaws\.com/[\w.\-]+', re.IGNORECASE)
    RE_FIREBASE = re.compile(r'[\w.\-]+\.firebaseio\.com|[\w.\-]+\.firebaseapp\.com', re.IGNORECASE)
    RE_AZURE_BLOB = re.compile(r'[\w.\-]+\.blob\.core\.windows\.net', re.IGNORECASE)
    RE_GCP_STORAGE = re.compile(r'storage\.googleapis\.com/[\w.\-]+|[\w.\-]+\.storage\.googleapis\.com', re.IGNORECASE)
    RE_OAUTH = re.compile(r'https?://[^\s"\']+/(?:oauth2?|authorize|token|\.well-known/openid)[^\s"\']*', re.IGNORECASE)
    RE_WS = re.compile(r'wss?://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.ASCII)
    RE_DEEP_LINK = re.compile(r'["\']([a-zA-Z][a-zA-Z0-9+.\-]+://?[^\s"\']{2,})["\']')
    RE_PARAM_KEY = re.compile(r'[?&](api[_-]?key|token|access[_-]?token|secret|auth|key|password|client[_-]?id|client[_-]?secret)=', re.IGNORECASE)
    RE_DOMAIN = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b')

    INTERNAL_IP_RANGES = [
        (re.compile(r'^10\.'), "10.x.x.x (Clase A privada)"),
        (re.compile(r'^192\.168\.'), "192.168.x.x (Clase C privada)"),
        (re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'), "172.16-31.x.x (Clase B privada)"),
        (re.compile(r'^127\.'), "127.x.x.x (loopback)"),
    ]

    SCAN_EXTENSIONS = {".smali", ".xml", ".json", ".js"}

    @staticmethod
    def _is_noise_domain(domain):
        d = domain.lower().rstrip(".")
        for noise in EndpointExtractor.NOISE_DOMAINS:
            if d == noise or d.endswith("." + noise):
                return True
        return False

    @staticmethod
    def _classify_ip(ip_str):
        """Retorna (es_interna, descripcion) o None si IP invalida."""
        parts = ip_str.split(".")
        if len(parts) != 4:
            return None
        try:
            if not all(0 <= int(p) <= 255 for p in parts):
                return None
        except ValueError:
            return None
        for pattern, desc in EndpointExtractor.INTERNAL_IP_RANGES:
            if pattern.match(ip_str):
                return (True, desc)
        return (False, "IP publica")

    @staticmethod
    def analyze(decompiled_dir):
        result = {
            "available": False,
            "total_endpoints": 0,
            "endpoints_by_type": {
                "api_endpoints": [],
                "domains": [],
                "cloud_resources": [],
                "auth_endpoints": [],
                "websocket_graphql": [],
                "deep_links": [],
                "internal_ips": [],
                "interesting_params": [],
            },
            "by_severity": {"CRITICO": [], "ALTO": [], "MEDIO": [], "INFO": []},
            "unique_domains": [],
            "summary": "",
        }

        if not decompiled_dir or not os.path.isdir(decompiled_dir):
            return result

        seen_urls = set()
        seen_domains = set()
        seen_ips = set()
        all_domains_unique = set()

        try:
            for root, _dirs, files in os.walk(decompiled_dir):
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in EndpointExtractor.SCAN_EXTENSIONS:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                    except Exception:
                        continue

                    rel_path = os.path.relpath(fpath, decompiled_dir)

                    # URLs HTTP/HTTPS
                    for m in EndpointExtractor.RE_URL.finditer(content):
                        url = m.group(0).rstrip('")>};,\'')
                        if url in seen_urls:
                            continue
                        seen_urls.add(url)
                        try:
                            domain = url.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
                        except IndexError:
                            domain = ""
                        if EndpointExtractor._is_noise_domain(domain):
                            continue
                        all_domains_unique.add(domain)

                        entry = {"url": url, "file": rel_path, "domain": domain}

                        # Clasificar
                        if EndpointExtractor.RE_S3.search(url):
                            entry["severity"] = "ALTO"
                            entry["subtype"] = "AWS S3"
                            result["endpoints_by_type"]["cloud_resources"].append(entry)
                            result["by_severity"]["ALTO"].append(entry)
                        elif EndpointExtractor.RE_FIREBASE.search(url):
                            entry["severity"] = "ALTO"
                            entry["subtype"] = "Firebase"
                            result["endpoints_by_type"]["cloud_resources"].append(entry)
                            result["by_severity"]["ALTO"].append(entry)
                        elif EndpointExtractor.RE_AZURE_BLOB.search(url):
                            entry["severity"] = "ALTO"
                            entry["subtype"] = "Azure Blob"
                            result["endpoints_by_type"]["cloud_resources"].append(entry)
                            result["by_severity"]["ALTO"].append(entry)
                        elif EndpointExtractor.RE_GCP_STORAGE.search(url):
                            entry["severity"] = "ALTO"
                            entry["subtype"] = "GCP Storage"
                            result["endpoints_by_type"]["cloud_resources"].append(entry)
                            result["by_severity"]["ALTO"].append(entry)
                        elif EndpointExtractor.RE_OAUTH.match(url):
                            entry["severity"] = "ALTO"
                            result["endpoints_by_type"]["auth_endpoints"].append(entry)
                            result["by_severity"]["ALTO"].append(entry)
                        else:
                            entry["severity"] = "MEDIO"
                            result["endpoints_by_type"]["api_endpoints"].append(entry)
                            result["by_severity"]["MEDIO"].append(entry)

                        # Parametros interesantes en la URL
                        if EndpointExtractor.RE_PARAM_KEY.search(url):
                            p_entry = {"url": url, "file": rel_path, "severity": "CRITICO"}
                            result["endpoints_by_type"]["interesting_params"].append(p_entry)
                            result["by_severity"]["CRITICO"].append(p_entry)

                    # WebSocket
                    for m in EndpointExtractor.RE_WS.finditer(content):
                        ws_url = m.group(0).rstrip('")>};,\'')
                        if ws_url in seen_urls:
                            continue
                        seen_urls.add(ws_url)
                        entry = {"url": ws_url, "file": rel_path, "severity": "MEDIO"}
                        result["endpoints_by_type"]["websocket_graphql"].append(entry)
                        result["by_severity"]["MEDIO"].append(entry)

                    # API paths relativos
                    for m in EndpointExtractor.RE_API_PATH.finditer(content):
                        path_val = m.group(1)
                        key = ("path", path_val)
                        if key in seen_urls:
                            continue
                        seen_urls.add(key)
                        entry = {"path": path_val, "file": rel_path, "severity": "MEDIO"}
                        if any(kw in path_val.lower() for kw in ("/auth", "/login", "/token", "/oauth")):
                            entry["severity"] = "ALTO"
                            result["endpoints_by_type"]["auth_endpoints"].append(entry)
                            result["by_severity"]["ALTO"].append(entry)
                        elif "/graphql" in path_val.lower():
                            result["endpoints_by_type"]["websocket_graphql"].append(entry)
                            result["by_severity"]["MEDIO"].append(entry)
                        else:
                            result["endpoints_by_type"]["api_endpoints"].append(entry)
                            result["by_severity"]["MEDIO"].append(entry)

                    # IPs
                    for m in EndpointExtractor.RE_IP.finditer(content):
                        ip = m.group(1)
                        if ip in seen_ips:
                            continue
                        seen_ips.add(ip)
                        cls = EndpointExtractor._classify_ip(ip)
                        if cls is None:
                            continue
                        is_internal, desc = cls
                        if is_internal:
                            entry = {"ip": ip, "file": rel_path, "range": desc, "severity": "CRITICO"}
                            result["endpoints_by_type"]["internal_ips"].append(entry)
                            result["by_severity"]["CRITICO"].append(entry)

                    # Deep links (esquemas custom, excluir http/https/file/content)
                    for m in EndpointExtractor.RE_DEEP_LINK.finditer(content):
                        dl = m.group(1)
                        scheme = dl.split(":", 1)[0].lower()
                        if scheme in ("http", "https", "file", "content", "android-resource",
                                      "android", "res", "jar", "data"):
                            continue
                        if dl in seen_urls:
                            continue
                        seen_urls.add(dl)
                        entry = {"uri": dl, "scheme": scheme, "file": rel_path, "severity": "INFO"}
                        result["endpoints_by_type"]["deep_links"].append(entry)
                        result["by_severity"]["INFO"].append(entry)

                    # Dominios sueltos (solo en smali)
                    if ext == ".smali":
                        for m in EndpointExtractor.RE_DOMAIN.finditer(content):
                            dom = m.group(1).lower()
                            if dom in seen_domains or EndpointExtractor._is_noise_domain(dom):
                                continue
                            # Filtrar extensiones de archivo comunes
                            tld = dom.rsplit(".", 1)[-1]
                            if tld in ("smali", "class", "java", "xml", "json", "png",
                                       "jpg", "gif", "dex", "so", "apk", "jar", "properties"):
                                continue
                            seen_domains.add(dom)
                            all_domains_unique.add(dom)
                            entry = {"domain": dom, "file": rel_path, "severity": "INFO"}
                            result["endpoints_by_type"]["domains"].append(entry)
                            result["by_severity"]["INFO"].append(entry)

            total = sum(len(v) for v in result["endpoints_by_type"].values())
            result["total_endpoints"] = total
            result["available"] = True
            result["unique_domains"] = sorted(all_domains_unique)

            parts = []
            for cat, items in result["endpoints_by_type"].items():
                if items:
                    parts.append(f"{len(items)} {cat}")
            result["summary"] = f"EndpointExtractor: {total} hallazgos — " + ", ".join(parts) if parts else "EndpointExtractor: sin hallazgos"

        except Exception as e:
            logger.debug(f"EndpointExtractor error: {e}")
            result["summary"] = f"EndpointExtractor: error ({e})"

        return result


# ====================================================================
# MODULO 8I: INJECTION ANALYZER - DETECCION DE INYECCIONES
# ====================================================================

class InjectionAnalyzer:
    """Deteccion offline de vulnerabilidades de inyeccion mediante patrones smali."""

    # --- SQL Injection ---
    RE_RAW_QUERY = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*L[^;]+;->(?:rawQuery|execSQL)\(', re.IGNORECASE)
    RE_SQL_CONCAT = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Ljava/lang/StringBuilder;->append\(')
    RE_CONTENT_QUERY = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/content/ContentResolver;->query\(')

    # --- WebView ---
    RE_LOAD_URL = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/WebView;->loadUrl\(')
    RE_LOAD_DATA = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/WebView;->(?:loadData|loadDataWithBaseURL)\(')
    RE_JS_ENABLED = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/WebSettings;->setJavaScriptEnabled\(')
    RE_JS_INTERFACE = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/WebView;->addJavascriptInterface\(')
    RE_EVAL_JS = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/WebView;->evaluateJavascript\(')
    RE_FILE_ACCESS = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/WebSettings;->(?:setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)\(')

    # --- Intent/IPC ---
    RE_GET_EXTRA = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/content/Intent;->(?:getStringExtra|getExtras|getData|getDataString)\(')
    RE_PENDING_MUTABLE = re.compile(r'const(?:/\d+)?\s+[vp]\d+,\s+0x(0|2)(?:\s|$)')  # FLAG_MUTABLE=0x2000000 o sin flag

    # --- Path Traversal ---
    RE_NEW_FILE_EXTRA = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/content/Intent;->getStringExtra\(.*?new-instance\s+[vp]\d+,\s+Ljava/io/File;', re.DOTALL)
    RE_FILE_INPUT = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Landroid/content/Context;->(?:openFileInput|openFileOutput)\(')
    RE_DOTDOT = re.compile(r'const-string\s+[vp]\d+,\s+"[^"]*\.\.[/\\][^"]*"')

    # --- Command Injection ---
    RE_RUNTIME_EXEC = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*Ljava/lang/Runtime;->exec\(')
    RE_PROCESS_BUILDER = re.compile(r'new-instance\s+[vp]\d+,\s+Ljava/lang/ProcessBuilder;')

    # --- Deserialization ---
    RE_OBJ_INPUT = re.compile(r'new-instance\s+[vp]\d+,\s+Ljava/io/ObjectInputStream;')
    RE_READ_SERIAL = re.compile(r'invoke-virtual\s+\{[^}]*\},\s*L[^;]+;->(?:readSerializable|readParcelable)\(')
    RE_CLASSLOADER = re.compile(r'new-instance\s+[vp]\d+,\s+L(?:dalvik/system/(?:DexClassLoader|PathClassLoader)|java/net/URLClassLoader);')

    # --- Log Injection ---
    RE_LOG_SENSITIVE = re.compile(
        r'invoke-static\s+\{[^}]*\},\s*Landroid/util/Log;->(?:d|i|w|e|v)\('
    )
    RE_SENSITIVE_STRING = re.compile(
        r'const-string\s+[vp]\d+,\s+"[^"]*(?:password|passwd|token|secret|credential|api[_-]?key|private[_-]?key)[^"]*"',
        re.IGNORECASE
    )

    @staticmethod
    def analyze(decompiled_dir, manifest_data=None):
        result = {
            "available": False,
            "total_vulnerabilities": 0,
            "vulnerabilities_by_type": {
                "sql_injection": [],
                "webview_injection": [],
                "intent_injection": [],
                "path_traversal": [],
                "command_injection": [],
                "deserialization": [],
                "log_injection": [],
            },
            "by_severity": {"CRITICO": [], "ALTO": [], "MEDIO": []},
            "exported_attack_surface": [],
            "summary": "",
        }

        if not decompiled_dir or not os.path.isdir(decompiled_dir):
            return result

        if manifest_data is None:
            manifest_data = {}

        # Componentes exportados (superficie de ataque)
        exported_names = set()
        for comp in manifest_data.get("exported_components", []):
            name = comp.get("name", "") if isinstance(comp, dict) else str(comp)
            if name:
                exported_names.add(name.split(".")[-1])

        def _add(vuln_type, severity, desc, file_path, line_hint=""):
            entry = {
                "type": vuln_type,
                "severity": severity,
                "description": desc,
                "file": file_path,
                "line_hint": line_hint,
            }
            result["vulnerabilities_by_type"][vuln_type].append(entry)
            result["by_severity"].setdefault(severity, []).append(entry)

            # Marcar si el componente es exportado
            base = os.path.basename(file_path).replace(".smali", "")
            if base in exported_names:
                if not any(e.get("component") == base for e in result["exported_attack_surface"]):
                    result["exported_attack_surface"].append({
                        "component": base,
                        "type": vuln_type,
                        "severity": severity,
                    })

        try:
            for root, _dirs, files in os.walk(decompiled_dir):
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext != ".smali":
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                    except Exception:
                        continue

                    rel_path = os.path.relpath(fpath, decompiled_dir)

                    # --- SQL Injection ---
                    has_raw_query = bool(InjectionAnalyzer.RE_RAW_QUERY.search(content))
                    has_concat = bool(InjectionAnalyzer.RE_SQL_CONCAT.search(content))
                    if has_raw_query and has_concat:
                        _add("sql_injection", "CRITICO",
                             "rawQuery/execSQL con concatenacion de strings (posible SQLi)",
                             rel_path)
                    elif has_raw_query:
                        _add("sql_injection", "ALTO",
                             "Uso de rawQuery/execSQL (verificar parametrizacion)",
                             rel_path)

                    if InjectionAnalyzer.RE_CONTENT_QUERY.search(content) and has_concat:
                        _add("sql_injection", "ALTO",
                             "ContentResolver.query() con concatenacion de seleccion",
                             rel_path)

                    # --- WebView Injection ---
                    has_js_enabled = bool(InjectionAnalyzer.RE_JS_ENABLED.search(content))
                    has_js_interface = bool(InjectionAnalyzer.RE_JS_INTERFACE.search(content))
                    has_load_url = bool(InjectionAnalyzer.RE_LOAD_URL.search(content))
                    has_load_data = bool(InjectionAnalyzer.RE_LOAD_DATA.search(content))
                    has_eval_js = bool(InjectionAnalyzer.RE_EVAL_JS.search(content))
                    has_file_access = bool(InjectionAnalyzer.RE_FILE_ACCESS.search(content))

                    if has_js_enabled and has_js_interface:
                        _add("webview_injection", "ALTO",
                             "JavaScript habilitado + addJavascriptInterface (posible XSS/RCE)",
                             rel_path)
                    if (has_load_url or has_load_data) and has_js_enabled:
                        _add("webview_injection", "ALTO",
                             "WebView.loadUrl/loadData con JavaScript habilitado",
                             rel_path)
                    if has_eval_js:
                        _add("webview_injection", "ALTO",
                             "evaluateJavascript() detectado (verificar input)",
                             rel_path)
                    if has_file_access:
                        _add("webview_injection", "ALTO",
                             "Acceso a archivos habilitado en WebView",
                             rel_path)

                    # --- Intent/IPC Injection ---
                    has_get_extra = bool(InjectionAnalyzer.RE_GET_EXTRA.search(content))
                    if has_get_extra and (has_raw_query or has_load_url or has_load_data):
                        _add("intent_injection", "ALTO",
                             "Datos de Intent usados en operacion sensible (query/WebView)",
                             rel_path)
                    if has_get_extra and bool(re.search(r'new-instance\s+[vp]\d+,\s+Ljava/io/File;', content)):
                        _add("intent_injection", "ALTO",
                             "Datos de Intent usados para construir rutas de archivo",
                             rel_path)

                    # PendingIntent mutable
                    if re.search(r'invoke-static\s+\{[^}]*\},\s*Landroid/app/PendingIntent;->(?:getActivity|getService|getBroadcast)\(', content):
                        # Buscar si NO usa FLAG_IMMUTABLE (0x4000000)
                        if not re.search(r'const(?:/high16)?\s+[vp]\d+,\s+0x4000000', content):
                            _add("intent_injection", "ALTO",
                                 "PendingIntent sin FLAG_IMMUTABLE (potencialmente mutable)",
                                 rel_path)

                    # --- Path Traversal ---
                    if InjectionAnalyzer.RE_DOTDOT.search(content):
                        _add("path_traversal", "ALTO",
                             "Patron ../ hardcodeado en string (posible path traversal)",
                             rel_path)
                    if has_get_extra and InjectionAnalyzer.RE_FILE_INPUT.search(content):
                        _add("path_traversal", "ALTO",
                             "openFileInput/Output con datos potencialmente externos",
                             rel_path)

                    # --- Command Injection ---
                    has_exec = bool(InjectionAnalyzer.RE_RUNTIME_EXEC.search(content))
                    has_pb = bool(InjectionAnalyzer.RE_PROCESS_BUILDER.search(content))
                    if has_exec and has_concat:
                        _add("command_injection", "CRITICO",
                             "Runtime.exec() con concatenacion de strings (posible command injection)",
                             rel_path)
                    elif has_exec:
                        _add("command_injection", "CRITICO",
                             "Runtime.exec() detectado (verificar input)",
                             rel_path)
                    if has_pb and has_concat:
                        _add("command_injection", "CRITICO",
                             "ProcessBuilder con argumentos dinamicos",
                             rel_path)
                    elif has_pb:
                        _add("command_injection", "ALTO",
                             "ProcessBuilder detectado",
                             rel_path)

                    # --- Deserialization ---
                    if InjectionAnalyzer.RE_OBJ_INPUT.search(content):
                        _add("deserialization", "CRITICO",
                             "ObjectInputStream detectado (posible deserializacion insegura)",
                             rel_path)
                    if InjectionAnalyzer.RE_READ_SERIAL.search(content):
                        _add("deserialization", "CRITICO",
                             "readSerializable/readParcelable de fuente potencialmente no confiable",
                             rel_path)
                    if InjectionAnalyzer.RE_CLASSLOADER.search(content):
                        _add("deserialization", "CRITICO",
                             "ClassLoader dinamico (DexClassLoader/PathClassLoader/URLClassLoader)",
                             rel_path)

                    # --- Log Injection ---
                    has_log = bool(InjectionAnalyzer.RE_LOG_SENSITIVE.search(content))
                    has_sensitive_str = bool(InjectionAnalyzer.RE_SENSITIVE_STRING.search(content))
                    if has_log and has_sensitive_str:
                        _add("log_injection", "MEDIO",
                             "Log.x() con datos potencialmente sensibles (password/token/key/secret)",
                             rel_path)

            total = sum(len(v) for v in result["vulnerabilities_by_type"].values())
            result["total_vulnerabilities"] = total
            result["available"] = True

            parts = []
            for cat, items in result["vulnerabilities_by_type"].items():
                if items:
                    parts.append(f"{len(items)} {cat}")
            result["summary"] = (
                f"InjectionAnalyzer: {total} vulnerabilidades — " + ", ".join(parts)
                if parts else "InjectionAnalyzer: sin vulnerabilidades detectadas"
            )

        except Exception as e:
            logger.debug(f"InjectionAnalyzer error: {e}")
            result["summary"] = f"InjectionAnalyzer: error ({e})"

        return result


# ====================================================================
# MODULO 8I-B: OWASP MOBILE TOP 10 2024 - DETECCION AUTOMATICA
# ====================================================================

class OWASPMobileTop10Analyzer:
    """Evalúa las 10 categorías OWASP Mobile Top 10 2024 sobre los datos del análisis."""

    WEIGHT_HIGH = 1.5
    WEIGHT_NORMAL = 1.0
    CATEGORY_WEIGHTS = {
        "M1": 1.5, "M2": 1.0, "M3": 1.0, "M4": 1.5, "M5": 1.5,
        "M6": 1.0, "M7": 1.0, "M8": 1.0, "M9": 1.0, "M10": 1.5,
    }

    RECOMMENDATIONS = {
        "M1": "Usar Android Keystore para almacenar credenciales. Nunca incluir claves API o contraseñas en el código fuente. Implementar rotación de tokens y almacenamiento cifrado.",
        "M2": "Auditar todas las dependencias de terceros con herramientas SCA. Limitar el número de SDKs de rastreo. Verificar firmas y hashes de librerías nativas.",
        "M3": "Implementar autenticación biométrica con CryptoObject vinculado. Proteger actividades exportadas con permisos. Usar tokens de sesión con expiración corta.",
        "M4": "Validar y sanitizar toda entrada de usuario. Usar consultas parametrizadas. Deshabilitar JavaScript en WebViews que no lo requieran. Validar URIs de Intent.",
        "M5": "Implementar certificate pinning. Deshabilitar tráfico en texto claro en network_security_config. Usar TLS 1.2+ y verificar cadenas de certificados.",
        "M6": "Solicitar solo permisos estrictamente necesarios. Eliminar SDKs de rastreo innecesarios. No registrar datos personales (PII) en logs.",
        "M7": "Aplicar ofuscación con R8/ProGuard. Habilitar detección de root y anti-tampering. Deshabilitar depuración en producción. Eliminar símbolos de depuración.",
        "M8": "Establecer debuggable=false y allowBackup=false. Proteger componentes exportados con permisos. Configurar correctamente network_security_config.",
        "M9": "Usar EncryptedSharedPreferences y SQLCipher para datos sensibles. Evitar almacenamiento externo para datos privados. Cifrar bases de datos locales.",
        "M10": "Reemplazar MD5/SHA1/DES/RC4 por SHA-256/AES-GCM. No usar modo ECB. Generar claves con SecureRandom. Almacenar claves en Android Keystore.",
    }

    @staticmethod
    def _score_from_findings(findings):
        """Calcula puntuación 0-100 basada en severidad de hallazgos."""
        pts = 0
        for f in findings:
            s = f.get("severity", "BAJO")
            if s == "CRITICO":
                pts += 25
            elif s == "ALTO":
                pts += 15
            elif s == "MEDIO":
                pts += 8
            else:
                pts += 3
        return min(pts, 100)

    @staticmethod
    def _severity_from_score(score):
        if score >= 76:
            return "CRITICO"
        elif score >= 51:
            return "ALTO"
        elif score >= 26:
            return "MEDIO"
        return "BAJO"

    @staticmethod
    def _analyze_m1(data):
        """M1 - Improper Credential Usage."""
        findings = []
        secrets = data.get("secrets", {})
        if isinstance(secrets, dict):
            for cat, items in secrets.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    desc = item if isinstance(item, str) else str(item.get("value", item.get("match", "")))[:120]
                    cat_lower = cat.lower()
                    if any(k in cat_lower for k in ("private_key", "password", "passwd")):
                        findings.append({"description": f"Credencial sensible ({cat})", "evidence": desc, "severity": "CRITICO"})
                    elif any(k in cat_lower for k in ("api_key", "token", "secret", "key")):
                        findings.append({"description": f"Clave/token hardcodeado ({cat})", "evidence": desc, "severity": "ALTO"})
                    else:
                        findings.append({"description": f"Secreto detectado ({cat})", "evidence": desc, "severity": "MEDIO"})

        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if any(k in gname_l for k in ("hardcoded", "credential", "password", "api_key")):
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"Patrón de credencial en smali: {gname}", "evidence": f"{count} ocurrencias", "severity": "ALTO"})

        endpoints = data.get("endpoints", {})
        if endpoints.get("available"):
            for ep_type, ep_list in endpoints.get("endpoints_by_type", {}).items():
                if not isinstance(ep_list, list):
                    continue
                for ep in ep_list:
                    url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
                    if re.search(r'(?:api[_-]?key|token|password|secret|auth)=\S+', url, re.IGNORECASE):
                        findings.append({"description": "URL con credencial embebida", "evidence": url[:120], "severity": "CRITICO"})

        return findings

    @staticmethod
    def _analyze_m2(data):
        """M2 - Inadequate Supply Chain Security."""
        findings = []
        trackers = data.get("trackers", {})
        total_trackers = trackers.get("total", 0)
        if total_trackers > 10:
            findings.append({"description": f"{total_trackers} trackers detectados (excesivo)", "evidence": f"Categorías: {', '.join(trackers.get('by_category', {}).keys())}", "severity": "ALTO"})
        elif total_trackers > 5:
            findings.append({"description": f"{total_trackers} trackers detectados", "evidence": f"Categorías: {', '.join(trackers.get('by_category', {}).keys())}", "severity": "MEDIO"})
        elif total_trackers > 0:
            findings.append({"description": f"{total_trackers} tracker(s) detectado(s)", "evidence": "", "severity": "BAJO"})

        apkid = data.get("apkid", {})
        if apkid.get("available"):
            packers = apkid.get("packers", [])
            if packers:
                findings.append({"description": f"Packer(s) detectado(s): riesgo de código oculto", "evidence": ", ".join(str(p) for p in packers[:5]), "severity": "MEDIO"})

        structure = data.get("structure", {})
        native_libs = structure.get("native_libs", [])
        if len(native_libs) > 20:
            findings.append({"description": f"{len(native_libs)} librerías nativas (superficie de ataque amplia)", "evidence": "", "severity": "MEDIO"})

        lief_data = data.get("lief", {})
        if lief_data.get("available"):
            suspicious = lief_data.get("suspicious_libs", [])
            for lib in suspicious[:5]:
                name = lib.get("name", str(lib)) if isinstance(lib, dict) else str(lib)
                findings.append({"description": "Librería nativa sospechosa", "evidence": name[:120], "severity": "ALTO"})

        return findings

    @staticmethod
    def _analyze_m3(data):
        """M3 - Insecure Authentication/Authorization."""
        findings = []
        banking = data.get("banking", {})
        if banking.get("available"):
            bio = banking.get("biometric_analysis", [])
            if isinstance(bio, list):
                for b in bio:
                    if isinstance(b, dict) and not b.get("crypto_bound", True):
                        findings.append({"description": "Biometría sin crypto-binding", "evidence": b.get("description", "")[:120], "severity": "ALTO"})
            if not bio:
                findings.append({"description": "Sin implementación biométrica detectada", "evidence": "Aplicación financiera sin biometría", "severity": "MEDIO"})

        manifest = data.get("manifest", {})
        exported = manifest.get("exported_components", [])
        for comp in exported:
            name = comp.get("name", str(comp)) if isinstance(comp, dict) else str(comp)
            name_l = name.lower()
            if any(k in name_l for k in ("login", "auth", "main", "launcher", "payment", "account")):
                findings.append({"description": "Actividad sensible exportada sin protección", "evidence": name[:120], "severity": "ALTO"})

        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if any(k in gname_l for k in ("webview", "javascript")):
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"WebView con posible bypass de autenticación: {gname}", "evidence": f"{count} ocurrencias", "severity": "MEDIO"})

        return findings

    @staticmethod
    def _analyze_m4(data):
        """M4 - Insufficient Input/Output Validation (usa datos de InjectionAnalyzer)."""
        findings = []
        injection = data.get("injection", {})
        if not injection.get("available"):
            return findings

        by_sev = injection.get("by_severity", {})
        for sev_key in ("CRITICO", "ALTO", "MEDIO", "BAJO"):
            items = by_sev.get(sev_key, [])
            if isinstance(items, list):
                for item in items[:10]:
                    if isinstance(item, dict):
                        findings.append({
                            "description": item.get("description", item.get("type", "Inyección")),
                            "evidence": f"{item.get('type','')}: {item.get('file','')}",
                            "severity": sev_key,
                        })

        return findings

    @staticmethod
    def _analyze_m5(data):
        """M5 - Insecure Communication."""
        findings = []
        network = data.get("network_security", {})
        if network.get("cleartext_permitted"):
            findings.append({"description": "Tráfico en texto claro permitido", "evidence": "cleartextTrafficPermitted=true", "severity": "CRITICO"})
        if not network.get("has_config"):
            findings.append({"description": "Sin network_security_config.xml", "evidence": "Configuración de red ausente", "severity": "ALTO"})
        if network.get("has_config") and not network.get("has_pinning"):
            findings.append({"description": "Sin certificate pinning configurado", "evidence": "network_security_config sin pin-set", "severity": "ALTO"})

        cert = data.get("certificate", {})
        if cert.get("is_signed") is False:
            findings.append({"description": "APK sin firma válida", "evidence": "", "severity": "CRITICO"})

        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if any(k in gname_l for k in ("trustmanager", "ssl", "hostname_verifier", "x509")):
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"Bypass de verificación TLS: {gname}", "evidence": f"{count} ocurrencias", "severity": "CRITICO"})

        forensic_db = data.get("forensic_db", {})
        if forensic_db.get("available"):
            pinning = forensic_db.get("cert_pinning_analysis", [])
            if isinstance(pinning, list) and not pinning:
                findings.append({"description": "Sin implementación de cert pinning en código", "evidence": "", "severity": "MEDIO"})

        return findings

    @staticmethod
    def _analyze_m6(data):
        """M6 - Inadequate Privacy Controls."""
        findings = []
        manifest = data.get("manifest", {})
        dangerous_perms = manifest.get("dangerous_permission_details", [])
        privacy_perms = ("LOCATION", "CONTACTS", "CAMERA", "MICROPHONE", "PHONE", "SMS",
                         "CALENDAR", "CALL_LOG", "READ_EXTERNAL", "BODY_SENSORS")
        for perm in dangerous_perms:
            pname = perm.get("name", str(perm)) if isinstance(perm, dict) else str(perm)
            if any(p in pname.upper() for p in privacy_perms):
                findings.append({"description": f"Permiso sensible para privacidad: {pname.split('.')[-1]}", "evidence": pname, "severity": "MEDIO"})

        trackers = data.get("trackers", {})
        total_t = trackers.get("total", 0)
        if total_t > 5:
            findings.append({"description": f"{total_t} trackers: riesgo de privacidad", "evidence": "", "severity": "ALTO"})

        injection = data.get("injection", {})
        log_inj = injection.get("log_injection", []) if isinstance(injection, dict) else []
        if isinstance(log_inj, list) and log_inj:
            findings.append({"description": f"{len(log_inj)} puntos de log injection (PII en logs)", "evidence": "", "severity": "ALTO"})

        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if any(k in gname_l for k in ("device_id", "imei", "android_id", "fingerprint", "advertising_id")):
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"Recolección de ID de dispositivo: {gname}", "evidence": f"{count} ocurrencias", "severity": "ALTO"})

        return findings

    @staticmethod
    def _analyze_m7(data):
        """M7 - Insufficient Binary Protections."""
        findings = []
        apkid = data.get("apkid", {})
        if apkid.get("available"):
            if not apkid.get("obfuscators"):
                findings.append({"description": "Sin ofuscación detectada (APKiD)", "evidence": "No se encontraron obfuscators", "severity": "ALTO"})
            if not apkid.get("protectors"):
                findings.append({"description": "Sin protectores de binario (APKiD)", "evidence": "No se encontraron protectors", "severity": "MEDIO"})
            if not apkid.get("anti_analysis"):
                findings.append({"description": "Sin técnicas anti-análisis (APKiD)", "evidence": "", "severity": "MEDIO"})

        banking = data.get("banking", {})
        if banking.get("available"):
            at = banking.get("anti_tampering", [])
            if isinstance(at, list) and not at:
                findings.append({"description": "Sin anti-tampering detectado", "evidence": "", "severity": "ALTO"})
            rd = banking.get("root_detection", [])
            if isinstance(rd, list) and not rd:
                findings.append({"description": "Sin detección de root", "evidence": "", "severity": "ALTO"})

        manifest = data.get("manifest", {})
        flags = manifest.get("flags", {})
        if flags.get("debuggable"):
            findings.append({"description": "Aplicación depurable (debuggable=true)", "evidence": "android:debuggable=true", "severity": "CRITICO"})

        lief_data = data.get("lief", {})
        if lief_data.get("available"):
            libs_detail = lief_data.get("libraries_detail", [])
            if isinstance(libs_detail, list):
                for lib in libs_detail:
                    if isinstance(lib, dict) and not lib.get("stripped", True):
                        findings.append({"description": f"Librería nativa con símbolos de depuración", "evidence": lib.get("name", "")[:80], "severity": "MEDIO"})

        entropy = data.get("entropy_obfuscation", {})
        if entropy.get("available"):
            obf_score = entropy.get("obfuscation_score", 100)
            if obf_score < 30:
                findings.append({"description": f"Bajo nivel de ofuscación (score={obf_score}/100)", "evidence": "Código fácilmente reversible", "severity": "ALTO"})
            elif obf_score < 50:
                findings.append({"description": f"Ofuscación moderada (score={obf_score}/100)", "evidence": "", "severity": "MEDIO"})

        return findings

    @staticmethod
    def _analyze_m8(data):
        """M8 - Security Misconfiguration."""
        findings = []
        manifest = data.get("manifest", {})
        flags = manifest.get("flags", {})

        if flags.get("debuggable"):
            findings.append({"description": "debuggable=true en producción", "evidence": "android:debuggable=true", "severity": "CRITICO"})
        if flags.get("allowBackup") or flags.get("allowBackup") is None:
            findings.append({"description": "allowBackup habilitado (extracción de datos posible)", "evidence": "android:allowBackup=true", "severity": "ALTO"})
        if flags.get("usesCleartextTraffic"):
            findings.append({"description": "usesCleartextTraffic=true", "evidence": "Tráfico HTTP permitido", "severity": "ALTO"})
        if flags.get("testOnly"):
            findings.append({"description": "testOnly=true (build de pruebas)", "evidence": "", "severity": "CRITICO"})

        exported = manifest.get("exported_components", [])
        if len(exported) > 10:
            findings.append({"description": f"{len(exported)} componentes exportados (superficie de ataque amplia)", "evidence": "", "severity": "ALTO"})
        elif len(exported) > 5:
            findings.append({"description": f"{len(exported)} componentes exportados", "evidence": "", "severity": "MEDIO"})

        network = data.get("network_security", {})
        if network.get("cleartext_permitted"):
            findings.append({"description": "Red: tráfico en texto claro habilitado", "evidence": "", "severity": "ALTO"})

        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if any(k in gname_l for k in ("setjavascriptenabled", "setallowfileaccess", "mixedcontent")):
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"WebView configuración insegura: {gname}", "evidence": f"{count} ocurrencias", "severity": "MEDIO"})

        return findings

    @staticmethod
    def _analyze_m9(data):
        """M9 - Insecure Data Storage."""
        findings = []
        forensic_db = data.get("forensic_db", {})
        if forensic_db.get("available"):
            dbs = forensic_db.get("databases", [])
            if isinstance(dbs, list):
                for db in dbs:
                    encrypted = db.get("encrypted", True) if isinstance(db, dict) else True
                    if not encrypted:
                        name = db.get("name", db.get("path", "")) if isinstance(db, dict) else str(db)
                        findings.append({"description": "Base de datos sin cifrar", "evidence": str(name)[:120], "severity": "ALTO"})

        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if "mode_world" in gname_l or "world_readable" in gname_l or "world_writable" in gname_l:
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"SharedPreferences con acceso mundial: {gname}", "evidence": f"{count} ocurrencias", "severity": "CRITICO"})
            if "sharedpreferences" in gname_l or "getshared" in gname_l:
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    findings.append({"description": f"Uso de SharedPreferences (verificar cifrado)", "evidence": f"{count} ocurrencias", "severity": "BAJO"})

        secrets = data.get("secrets", {})
        if isinstance(secrets, dict):
            total_s = sum(len(v) for v in secrets.values() if isinstance(v, list))
            if total_s > 10:
                findings.append({"description": f"{total_s} secretos almacenados en texto plano", "evidence": "", "severity": "ALTO"})

        deobf = data.get("string_deobfuscation", {})
        if deobf.get("available") and deobf.get("total_decoded", 0) > 0:
            interesting = deobf.get("interesting_strings", [])
            if interesting:
                findings.append({"description": f"{len(interesting)} strings sensibles decodificadas", "evidence": "", "severity": "MEDIO"})

        structure = data.get("structure", {})
        for f_path in structure.get("suspicious_assets", []):
            fp = f_path if isinstance(f_path, str) else str(f_path.get("path", f_path) if isinstance(f_path, dict) else f_path)
            if "external" in fp.lower() or "sdcard" in fp.lower():
                findings.append({"description": "Referencia a almacenamiento externo", "evidence": fp[:120], "severity": "MEDIO"})

        return findings

    @staticmethod
    def _analyze_m10(data):
        """M10 - Insufficient Cryptography."""
        findings = []
        smali = data.get("smali_analysis", {})
        grouped = smali.get("grouped", {})
        weak_crypto_patterns = ("md5", "sha1", "des", "rc4", "ecb", "weak_crypto", "insecure_random")
        for gname, gdata in grouped.items():
            gname_l = gname.lower()
            if any(k in gname_l for k in weak_crypto_patterns):
                count = gdata.get("count", 0) if isinstance(gdata, dict) else (len(gdata) if isinstance(gdata, list) else 0)
                if count > 0:
                    sev = "CRITICO" if any(k in gname_l for k in ("des", "rc4", "ecb")) else "ALTO"
                    findings.append({"description": f"Criptografía débil: {gname}", "evidence": f"{count} ocurrencias", "severity": sev})

        androguard = data.get("androguard", {})
        if androguard.get("available"):
            dangerous = androguard.get("dangerous_api_calls", [])
            if isinstance(dangerous, list):
                for call in dangerous:
                    call_str = call.get("method", str(call)) if isinstance(call, dict) else str(call)
                    if re.search(r'(?:Cipher|MessageDigest|SecretKey)', call_str):
                        if re.search(r'(?:DES|RC4|MD5|SHA-?1|ECB)', call_str, re.IGNORECASE):
                            findings.append({"description": "API criptográfica débil (Androguard)", "evidence": call_str[:120], "severity": "ALTO"})

        crypto_cert = data.get("crypto_cert", {})
        if crypto_cert.get("available"):
            anomalies = crypto_cert.get("cert_anomalies", [])
            if isinstance(anomalies, list):
                for a in anomalies:
                    a_str = a if isinstance(a, str) else str(a)
                    findings.append({"description": "Anomalía en certificado criptográfico", "evidence": a_str[:120], "severity": "MEDIO"})
            certs = crypto_cert.get("certificates", [])
            if isinstance(certs, list):
                for c in certs:
                    if isinstance(c, dict):
                        algo = c.get("signature_algorithm", "")
                        if re.search(r'(?:md5|sha1)', str(algo), re.IGNORECASE):
                            findings.append({"description": f"Certificado con algoritmo débil: {algo}", "evidence": "", "severity": "ALTO"})
                        key_size = c.get("public_key_size", 4096)
                        if isinstance(key_size, (int, float)) and key_size < 2048:
                            findings.append({"description": f"Clave de certificado pequeña: {key_size} bits", "evidence": "", "severity": "ALTO"})

        lief_data = data.get("lief", {})
        if lief_data.get("available"):
            dangerous_imp = lief_data.get("dangerous_imports_found", [])
            if isinstance(dangerous_imp, list):
                for imp in dangerous_imp:
                    fn = imp.get("function", str(imp)) if isinstance(imp, dict) else str(imp)
                    if re.search(r'(?:MD5|DES|RC4|rand\b)', fn, re.IGNORECASE):
                        findings.append({"description": f"Crypto débil en código nativo: {fn}", "evidence": "", "severity": "ALTO"})

        return findings

    @staticmethod
    def analyze(data):
        """Ejecuta el análisis completo OWASP Mobile Top 10 2024."""
        try:
            analyzers = {
                "M1": ("Improper Credential Usage", OWASPMobileTop10Analyzer._analyze_m1),
                "M2": ("Inadequate Supply Chain Security", OWASPMobileTop10Analyzer._analyze_m2),
                "M3": ("Insecure Authentication/Authorization", OWASPMobileTop10Analyzer._analyze_m3),
                "M4": ("Insufficient Input/Output Validation", OWASPMobileTop10Analyzer._analyze_m4),
                "M5": ("Insecure Communication", OWASPMobileTop10Analyzer._analyze_m5),
                "M6": ("Inadequate Privacy Controls", OWASPMobileTop10Analyzer._analyze_m6),
                "M7": ("Insufficient Binary Protections", OWASPMobileTop10Analyzer._analyze_m7),
                "M8": ("Security Misconfiguration", OWASPMobileTop10Analyzer._analyze_m8),
                "M9": ("Insecure Data Storage", OWASPMobileTop10Analyzer._analyze_m9),
                "M10": ("Insufficient Cryptography", OWASPMobileTop10Analyzer._analyze_m10),
            }

            categories = []
            total_findings = 0
            by_severity = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0}
            weighted_sum = 0.0
            weight_total = 0.0

            for mid, (name, func) in analyzers.items():
                try:
                    findings = func(data)
                except Exception as e:
                    logger.debug(f"OWASP {mid} error: {e}")
                    findings = []

                score = OWASPMobileTop10Analyzer._score_from_findings(findings)
                severity = OWASPMobileTop10Analyzer._severity_from_score(score)

                for f in findings:
                    sev = f.get("severity", "BAJO")
                    if sev in by_severity:
                        by_severity[sev] += 1

                total_findings += len(findings)
                w = OWASPMobileTop10Analyzer.CATEGORY_WEIGHTS.get(mid, 1.0)
                weighted_sum += score * w
                weight_total += w

                categories.append({
                    "id": mid,
                    "name": name,
                    "severity": severity,
                    "score": score,
                    "findings": findings,
                    "recommendation": OWASPMobileTop10Analyzer.RECOMMENDATIONS.get(mid, ""),
                })

            overall_score = int(weighted_sum / weight_total) if weight_total > 0 else 0
            overall_severity = OWASPMobileTop10Analyzer._severity_from_score(overall_score)

            summary_parts = [f"OWASP Mobile Top 10 2024: {total_findings} hallazgos"]
            for sev in ("CRITICO", "ALTO", "MEDIO", "BAJO"):
                cnt = by_severity[sev]
                if cnt > 0:
                    summary_parts.append(f"{cnt} {sev}")

            return {
                "available": True,
                "categories": categories,
                "overall_score": overall_score,
                "overall_severity": overall_severity,
                "total_findings": total_findings,
                "by_severity": by_severity,
                "summary": " | ".join(summary_parts),
            }

        except Exception as e:
            logger.error(f"OWASPMobileTop10Analyzer error: {e}")
            return {"available": False, "error": str(e), "summary": f"OWASP: error ({e})"}


# ====================================================================
# MODULO 8J: CRYPTOGRAPHY - ANALISIS PROFUNDO DE CERTIFICADOS
# ====================================================================

class CryptoCertAnalyzer:
    """Análisis profundo del certificado con la librería cryptography."""

    @staticmethod
    def analyze(apk_path):
        if not HAS_CRYPTOGRAPHY:
            return {"available": False, "error": "cryptography no instalado (pip install cryptography)"}

        result = {
            "available": True,
            "certificates": [],
            "shared_cert_warning": False,
            "weak_algorithms": [],
            "cert_anomalies": [],
            "summary": "",
        }

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                cert_files = [n for n in zf.namelist()
                              if n.startswith("META-INF/") and
                              any(n.upper().endswith(e) for e in (".RSA", ".DSA", ".EC"))]

                if not cert_files:
                    result["error"] = "No se encontraron certificados en META-INF/"
                    return result

                for cert_file in cert_files:
                    cert_data = zf.read(cert_file)
                    cert_info = CryptoCertAnalyzer._parse_cert(cert_data, cert_file)
                    if cert_info:
                        result["certificates"].append(cert_info)

                        # Verificar anomalías
                        CryptoCertAnalyzer._check_anomalies(cert_info, result)

        except Exception as e:
            result["error"] = str(e)

        certs = result["certificates"]
        result["summary"] = (
            f"Certificados: {len(certs)} encontrado(s), "
            f"{len(result['weak_algorithms'])} algoritmos débiles, "
            f"{len(result['cert_anomalies'])} anomalías"
        )

        return result

    @staticmethod
    def _parse_cert(cert_data, cert_file):
        info = {"file": cert_file}

        try:
            # PKCS#7 DER
            certs = pkcs7.load_der_pkcs7_certificates(cert_data)
            if not certs:
                return None

            cert = certs[0]  # Primer certificado

            # Subject
            subject = {}
            for attr in cert.subject:
                oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid.dotted_string)
                subject[oid_name] = attr.value
            info["subject"] = subject

            # Issuer
            issuer = {}
            for attr in cert.issuer:
                oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid.dotted_string)
                issuer[oid_name] = attr.value
            info["issuer"] = issuer

            # Validez
            info["not_valid_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
            info["not_valid_after"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)

            # Serial number
            info["serial_number"] = hex(cert.serial_number)

            # Algoritmo de firma
            sig_alg = cert.signature_algorithm_oid
            info["signature_algorithm_oid"] = sig_alg.dotted_string if hasattr(sig_alg, 'dotted_string') else str(sig_alg)
            info["signature_algorithm"] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

            # Clave pública
            pub_key = cert.public_key()
            info["public_key_type"] = type(pub_key).__name__
            info["public_key_size"] = pub_key.key_size if hasattr(pub_key, 'key_size') else 0

            # Self-signed
            info["is_self_signed"] = cert.subject == cert.issuer

            # Fingerprints
            info["sha1_fingerprint"] = cert.fingerprint(crypto_hashes.SHA1()).hex()
            info["sha256_fingerprint"] = cert.fingerprint(crypto_hashes.SHA256()).hex()

            # Extensiones
            extensions = []
            for ext in cert.extensions:
                try:
                    extensions.append({
                        "oid": ext.oid.dotted_string,
                        "name": ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid.dotted_string),
                        "critical": ext.critical,
                    })
                except Exception as e:
                    logger.debug(f"Error parseando extension de certificado: {e}")
            info["extensions"] = extensions

            # Validez temporal
            try:
                from datetime import timezone
                now = datetime.now(timezone.utc)
                # Ensure not_before/not_after are timezone-aware for comparison
                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
            except Exception:
                now = datetime.utcnow()
                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            info["is_expired"] = now > not_after
            info["validity_years"] = round((not_after - not_before).days / 365.25, 1)

        except Exception as e:
            info["parse_error"] = str(e)

        return info

    @staticmethod
    def _check_anomalies(cert_info, result):
        # Algoritmo débil
        sig_alg = cert_info.get("signature_algorithm", "").lower()
        if sig_alg in ("md5", "md2"):
            result["weak_algorithms"].append({"algorithm": sig_alg, "severity": "CRITICO"})
            result["cert_anomalies"].append(f"Algoritmo de firma {sig_alg.upper()} (totalmente inseguro)")
        elif sig_alg == "sha1":
            result["weak_algorithms"].append({"algorithm": sig_alg, "severity": "ALTO"})
            result["cert_anomalies"].append("Algoritmo SHA1 (depreciado)")

        # Clave pública pequeña
        key_size = cert_info.get("public_key_size", 0)
        if 0 < key_size < 2048:
            result["cert_anomalies"].append(f"Clave pública de {key_size} bits (mínimo recomendado: 2048)")

        # Certificado expirado
        if cert_info.get("is_expired"):
            result["cert_anomalies"].append("Certificado EXPIRADO")

        # Validez extremadamente larga (sospechoso en apps)
        validity = cert_info.get("validity_years", 0)
        if validity > 50:
            result["cert_anomalies"].append(f"Validez de {validity} años (sospechosamente largo)")

        # Subject genérico (Android debug o certificados por defecto)
        subject = cert_info.get("subject", {})
        cn = subject.get("commonName", "").lower()
        org = subject.get("organizationName", "").lower()
        if cn in ("android debug", "debug", "unknown"):
            result["cert_anomalies"].append(f"Certificado de DEBUG (CN={cn}) - NO apto para producción")
        if org in ("android", "unknown", ""):
            result["cert_anomalies"].append(f"Organización genérica: '{org}'")


# ====================================================================
# MODULO: FORENSIC DB EXTRACTOR - Offline forensic extraction/analysis
# ====================================================================

class ForensicDBExtractor:
    """Offline forensic extraction and analysis of Android app data stores."""

    @staticmethod
    def analyze(apk_path, decompiled_dir=None, structure_data=None):
        result = {
            "available": True,
            "databases": [],
            "keystore_usage": [],
            "advanced_yara_rules": "",
            "memory_forensics_commands": [],
            "cert_pinning_analysis": [],
            "summary": "",
        }

        try:
            file_contents = ForensicDBExtractor._collect_file_contents(apk_path, decompiled_dir)
            result["databases"] = ForensicDBExtractor._detect_databases(file_contents)
            result["keystore_usage"] = ForensicDBExtractor._detect_keystore(file_contents)
            result["advanced_yara_rules"] = ForensicDBExtractor._generate_yara_rules()
            result["memory_forensics_commands"] = ForensicDBExtractor._generate_memory_commands()
            result["cert_pinning_analysis"] = ForensicDBExtractor._detect_cert_pinning(file_contents)
        except Exception as e:
            result["available"] = False
            result["summary"] = f"Error during analysis: {e}"
            return result

        db_count = len(result["databases"])
        ks_count = len(result["keystore_usage"])
        pin_count = len(result["cert_pinning_analysis"])
        result["summary"] = (
            f"Databases/stores: {db_count}, Keystore usages: {ks_count}, "
            f"Cert pinning: {pin_count} findings"
        )
        return result

    @staticmethod
    def _collect_file_contents(apk_path, decompiled_dir):
        contents = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    lower = name.lower()
                    if any(lower.endswith(ext) for ext in ('.smali', '.xml', '.java', '.so', '.dex', '.kt')):
                        try:
                            data = zf.read(name)
                            try:
                                text = data.decode('utf-8', errors='ignore')
                            except Exception:
                                text = data.decode('latin-1', errors='ignore')
                            contents.append((name, text))
                        except Exception:
                            pass
        except Exception:
            pass

        if decompiled_dir and os.path.isdir(decompiled_dir):
            try:
                for root, _dirs, files in os.walk(decompiled_dir):
                    for fname in files:
                        lower = fname.lower()
                        if any(lower.endswith(ext) for ext in ('.smali', '.xml', '.java', '.kt')):
                            fpath = os.path.join(root, fname)
                            try:
                                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                                    text = f.read()
                                rel = os.path.relpath(fpath, decompiled_dir)
                                contents.append((rel, text))
                            except Exception:
                                pass
            except Exception:
                pass

        return contents

    @staticmethod
    def _detect_databases(file_contents):
        findings = []
        patterns = {
            "SQLCipher": {
                "patterns": [r'net\.sqlcipher', r'SQLiteDatabase\.loadLibs', r'sqlcipher'],
                "encryption": "encrypted",
                "risk": "Low",
            },
            "Room DB": {
                "patterns": [r'androidx\.room', r'@Database', r'@Entity', r'@Dao', r'RoomDatabase'],
                "encryption": "unencrypted (by default)",
                "risk": "Medium",
            },
            "Realm": {
                "patterns": [r'io\.realm', r'RealmConfiguration', r'librealm'],
                "encryption": "optional (key-based)",
                "risk": "Medium",
            },
            "MMKV": {
                "patterns": [r'com\.tencent\.mmkv', r'MMKV\.initialize', r'libmmkv\.so'],
                "encryption": "optional",
                "risk": "Medium",
            },
            "SharedPreferences": {
                "patterns": [r'getSharedPreferences', r'PreferenceManager'],
                "encryption": "unencrypted",
                "risk": "High",
            },
        }

        for file_path, text in file_contents:
            for db_type, info in patterns.items():
                for pat in info["patterns"]:
                    try:
                        matches = re.findall(pat, text)
                        if matches:
                            findings.append({
                                "type": db_type,
                                "evidence": {"file": file_path, "string_found": matches[0]},
                                "encryption_status": info["encryption"],
                                "risk_level": info["risk"],
                            })
                            break
                    except Exception:
                        pass

        seen = set()
        deduped = []
        for f in findings:
            key = (f["type"], f["evidence"]["file"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    @staticmethod
    def _detect_keystore(file_contents):
        findings = []
        patterns = {
            "AndroidKeyStore": {
                "patterns": [r'AndroidKeyStore', r'KeyStore\.getInstance\("AndroidKeyStore"\)'],
                "provider": "AndroidKeyStore",
                "key_type": "symmetric/asymmetric",
            },
            "KeyGenParameterSpec": {
                "patterns": [r'KeyGenParameterSpec'],
                "provider": "AndroidKeyStore",
                "key_type": "generated",
            },
            "UserAuthRequired": {
                "patterns": [r'setUserAuthenticationRequired'],
                "provider": "AndroidKeyStore",
                "key_type": "auth-bound",
            },
            "StrongBox": {
                "patterns": [r'setIsStrongBoxBacked'],
                "provider": "AndroidKeyStore",
                "key_type": "hardware-backed",
            },
            "BouncyCastle": {
                "patterns": [r'org\.bouncycastle', r'BouncyCastleProvider'],
                "provider": "BouncyCastle",
                "key_type": "software",
            },
            "HardwareBacked": {
                "patterns": [r'setAttestationChallenge', r'KEY_ALGORITHM_EC', r'PURPOSE_SIGN'],
                "provider": "AndroidKeyStore",
                "key_type": "hardware-attested",
            },
        }

        for file_path, text in file_contents:
            for usage_type, info in patterns.items():
                for pat in info["patterns"]:
                    try:
                        matches = re.findall(pat, text)
                        if matches:
                            hw_backed = usage_type in ("StrongBox", "HardwareBacked")
                            auth_required = "UserAuth" in usage_type or "setUserAuthenticationRequired" in text
                            findings.append({
                                "type": usage_type,
                                "file": file_path,
                                "evidence": matches[0],
                                "provider": info["provider"],
                                "key_type": info["key_type"],
                                "authentication_required": auth_required,
                                "hardware_backed": hw_backed,
                            })
                            break
                    except Exception:
                        pass

        seen = set()
        deduped = []
        for f in findings:
            key = (f["type"], f["file"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    @staticmethod
    def _generate_yara_rules():
        return '''rule Loki_Thor_Malware {
    meta:
        description = "Detects Loki/Thor malware indicators including C2 patterns and tor hidden services"
        category = "malware"
        severity = "critical"
    strings:
        $c2_1 = "fre.php" ascii
        $c2_2 = "/Panel/five/fre.php" ascii
        $loki_url = "http://" ascii
        $tor_1 = ".onion" ascii
        $tor_2 = "torproject" ascii
        $loki_ua = "Mozilla/4.08" ascii
        $loki_path = "/Main/index.php" ascii
        $thor_str = "thor" ascii nocase
    condition:
        any of ($c2_*) or (any of ($tor_*) and any of ($loki_*)) or $thor_str
}

rule Banking_Trojan_Deep {
    meta:
        description = "Detects banking trojan indicators including overlay attacks and accessibility abuse"
        category = "banking_trojan"
        severity = "critical"
    strings:
        $overlay_1 = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay_2 = "SYSTEM_ALERT_WINDOW" ascii
        $accessibility_1 = "AccessibilityService" ascii
        $accessibility_2 = "onAccessibilityEvent" ascii
        $accessibility_3 = "BIND_ACCESSIBILITY_SERVICE" ascii
        $screen_1 = "MediaProjection" ascii
        $screen_2 = "createScreenCapture" ascii
        $screen_3 = "MediaRecorder" ascii
        $inject_1 = "WebView" ascii
        $inject_2 = "evaluateJavascript" ascii
        $sms_intercept = "SMS_RECEIVED" ascii
    condition:
        (any of ($overlay_*) and any of ($accessibility_*)) or
        (any of ($screen_*) and any of ($accessibility_*)) or
        (any of ($inject_*) and $sms_intercept)
}

rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware indicators including file encryption and ransom note patterns"
        category = "ransomware"
        severity = "critical"
    strings:
        $enc_1 = "javax.crypto.Cipher" ascii
        $enc_2 = "AES/CBC/PKCS5Padding" ascii
        $enc_3 = "RSA/ECB/PKCS1Padding" ascii
        $ransom_1 = "your files have been encrypted" ascii nocase
        $ransom_2 = "pay bitcoin" ascii nocase
        $ransom_3 = "decrypt your files" ascii nocase
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $file_ext_1 = ".locked" ascii
        $file_ext_2 = ".encrypted" ascii
        $file_ext_3 = ".crypt" ascii
        $storage_1 = "WRITE_EXTERNAL_STORAGE" ascii
        $storage_2 = "getExternalStorageDirectory" ascii
    condition:
        (any of ($enc_*) and any of ($ransom_*)) or
        (any of ($enc_*) and $btc_addr) or
        (any of ($file_ext_*) and any of ($storage_*) and any of ($enc_*))
}

rule Stalkerware_Spyware_Deep {
    meta:
        description = "Detects stalkerware and spyware indicators including call recording and location tracking"
        category = "stalkerware"
        severity = "high"
    strings:
        $call_rec_1 = "PROCESS_OUTGOING_CALLS" ascii
        $call_rec_2 = "MediaRecorder.AudioSource" ascii
        $call_rec_3 = "RECORD_AUDIO" ascii
        $sms_fwd_1 = "SMS_RECEIVED" ascii
        $sms_fwd_2 = "SmsMessage" ascii
        $sms_fwd_3 = "sendTextMessage" ascii
        $loc_1 = "ACCESS_FINE_LOCATION" ascii
        $loc_2 = "requestLocationUpdates" ascii
        $loc_3 = "getLastKnownLocation" ascii
        $camera_1 = "android.hardware.camera" ascii
        $camera_2 = "takePicture" ascii
        $camera_3 = "CAMERA" ascii
        $hide_1 = "setComponentEnabledSetting" ascii
        $hide_2 = "COMPONENT_ENABLED_STATE_DISABLED" ascii
        $keylog = "onKey" ascii
    condition:
        (2 of ($call_rec_*)) or
        (2 of ($sms_fwd_*)) or
        (2 of ($loc_*) and any of ($camera_*)) or
        (any of ($hide_*) and (any of ($loc_*) or any of ($call_rec_*))) or
        ($keylog and any of ($hide_*))
}

rule Crypto_Wallet_Stealing {
    meta:
        description = "Detects crypto wallet stealing indicators including clipboard hijacking and wallet patterns"
        category = "crypto_theft"
        severity = "critical"
    strings:
        $clip_1 = "ClipboardManager" ascii
        $clip_2 = "setPrimaryClip" ascii
        $clip_3 = "getPrimaryClip" ascii
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $eth = /0x[0-9a-fA-F]{40}/ ascii
        $wallet_1 = "wallet" ascii nocase
        $wallet_2 = "bitcoin" ascii nocase
        $wallet_3 = "ethereum" ascii nocase
        $wallet_4 = "crypto" ascii nocase
        $replace_1 = "replaceAll" ascii
        $replace_2 = "Pattern.compile" ascii
    condition:
        (any of ($clip_*) and (any of ($btc, $eth))) or
        (2 of ($clip_*) and any of ($wallet_*) and any of ($replace_*)) or
        ($btc and $eth and any of ($clip_*))
}'''

    @staticmethod
    def _generate_memory_commands():
        commands = [
            {
                "tool": "volatility3",
                "category": "process_analysis",
                "commands": [
                    "vol -f memory.img linux.pslist",
                    "vol -f memory.img linux.pstree",
                    "vol -f memory.img linux.psaux",
                    "vol -f memory.img linux.proc.Maps --pid <PID>",
                ]
            },
            {
                "tool": "volatility3",
                "category": "network_connections",
                "commands": [
                    "vol -f memory.img linux.netstat",
                    "vol -f memory.img linux.sockstat",
                    "vol -f memory.img linux.netscan",
                ]
            },
            {
                "tool": "volatility3",
                "category": "open_files",
                "commands": [
                    "vol -f memory.img linux.lsof",
                    "vol -f memory.img linux.bash",
                    "vol -f memory.img linux.check_afinfo",
                ]
            },
            {
                "tool": "volatility3",
                "category": "dalvik_heap",
                "commands": [
                    "vol -f memory.img linux.proc.Maps --pid <PID> | grep dalvik",
                    "vol -f memory.img linux.dump --pid <PID> --dump",
                    "vol -f memory.img linux.elfs --pid <PID>",
                ]
            },
            {
                "tool": "rekall",
                "category": "process_analysis",
                "commands": [
                    "rekal -f memory.img pslist",
                    "rekal -f memory.img pstree",
                    "rekal -f memory.img memdump --pid <PID>",
                ]
            },
            {
                "tool": "rekall",
                "category": "network_connections",
                "commands": [
                    "rekal -f memory.img netstat",
                    "rekal -f memory.img connections",
                    "rekal -f memory.img sockets",
                ]
            },
            {
                "tool": "rekall",
                "category": "open_files",
                "commands": [
                    "rekal -f memory.img lsof",
                    "rekal -f memory.img handles --pid <PID>",
                ]
            },
            {
                "tool": "rekall",
                "category": "dalvik_heap",
                "commands": [
                    "rekal -f memory.img vaddump --pid <PID>",
                    "rekal -f memory.img maps --pid <PID>",
                    "rekal -f memory.img dump --pid <PID> --output heap_dump/",
                ]
            },
        ]
        return commands

    @staticmethod
    def _detect_cert_pinning(file_contents):
        findings = []
        patterns = {
            "Custom TrustManager": {
                "patterns": [r'checkServerTrusted', r'X509TrustManager'],
                "bypass_difficulty": "Easy",
            },
            "OkHttp CertificatePinner": {
                "patterns": [r'CertificatePinner\.Builder', r'sha256/'],
                "bypass_difficulty": "Medium",
            },
            "Flutter SSL Pinning": {
                "patterns": [r'SecurityContext', r'HandshakeException', r'badCertificateCallback'],
                "bypass_difficulty": "Hard",
            },
            "React Native SSL": {
                "patterns": [r'OkHttpClientProvider', r'SSLSocketFactory'],
                "bypass_difficulty": "Medium",
            },
            "Network Security Config": {
                "patterns": [r'network_security_config', r'pin-set', r'trust-anchors'],
                "bypass_difficulty": "Easy",
            },
        }

        for file_path, text in file_contents:
            for pin_type, info in patterns.items():
                matched_evidence = []
                for pat in info["patterns"]:
                    try:
                        matches = re.findall(pat, text)
                        if matches:
                            matched_evidence.append(matches[0])
                    except Exception:
                        pass
                if matched_evidence:
                    findings.append({
                        "type": pin_type,
                        "file": file_path,
                        "evidence": matched_evidence,
                        "bypass_difficulty": info["bypass_difficulty"],
                    })

        seen = set()
        deduped = []
        for f in findings:
            key = (f["type"], f["file"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped


# ====================================================================
# MODULO 8K: ANALISIS DINAMICO - GENERADOR DE SCRIPTS Y COMANDOS
# ====================================================================

class DynamicAnalysisGenerator:
    """Genera scripts Frida, comandos ADB, módulos Drozer, config de proxy
    y scripts de Objection para análisis dinámico/runtime del APK."""

    @staticmethod
    def generate(apk_path, manifest_data, output_dir, structure_data=None):
        """Genera todo el kit de análisis dinámico."""
        result = {
            "available": True,
            "package": manifest_data.get("package", ""),
            "scripts_generated": [],
            "frida_scripts": {},
            "adb_commands": [],
            "drozer_commands": [],
            "objection_commands": [],
            "proxy_config": {},
            "memory_dump_commands": [],
            "runtime_hooks": [],
            "summary": "",
        }

        pkg = manifest_data.get("package", "com.target.app")
        main_activity = ""
        for act in manifest_data.get("activities", []):
            for flt in act.get("intent_filters", []):
                for action in flt.get("actions", []):
                    if "MAIN" in action:
                        main_activity = act.get("name", "")
                        break

        dynamic_dir = os.path.join(output_dir, "dynamic_analysis")
        os.makedirs(dynamic_dir, exist_ok=True)

        # 1. Frida Scripts
        frida_scripts = DynamicAnalysisGenerator._gen_frida_scripts(
            pkg, main_activity, manifest_data, structure_data, dynamic_dir)
        result["frida_scripts"] = frida_scripts

        # 2. ADB Commands
        result["adb_commands"] = DynamicAnalysisGenerator._gen_adb_commands(
            pkg, main_activity, apk_path)

        # 3. Drozer Commands
        result["drozer_commands"] = DynamicAnalysisGenerator._gen_drozer_commands(
            pkg, manifest_data)

        # 4. Objection Commands
        result["objection_commands"] = DynamicAnalysisGenerator._gen_objection_commands(pkg)

        # 5. Proxy Configuration
        result["proxy_config"] = DynamicAnalysisGenerator._gen_proxy_config(pkg)

        # 6. Memory Dump Commands
        result["memory_dump_commands"] = DynamicAnalysisGenerator._gen_memory_commands(pkg)

        # 7. Runtime Hooks Summary
        result["runtime_hooks"] = DynamicAnalysisGenerator._gen_runtime_hooks(
            pkg, manifest_data, structure_data)

        # Guardar master script
        master_path = os.path.join(dynamic_dir, "00_README_DYNAMIC.md")
        DynamicAnalysisGenerator._gen_master_readme(
            master_path, pkg, main_activity, result)
        result["scripts_generated"].append(master_path)

        result["summary"] = (
            f"Kit dinámico: {len(frida_scripts)} scripts Frida, "
            f"{len(result['adb_commands'])} cmds ADB, "
            f"{len(result['drozer_commands'])} cmds Drozer, "
            f"{len(result['objection_commands'])} cmds Objection"
        )

        return result

    # ----------------------------------------------------------------
    # FRIDA SCRIPTS
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_frida_scripts(pkg, main_activity, manifest, structure, output_dir):
        scripts = {}

        # 1. SSL Pinning Bypass Universal
        ssl_bypass = r'''/* APKILIS - SSL Pinning Bypass Universal
 * Soporta: OkHttp3, TrustManager, Flutter, React Native, Xamarin
 * Uso: frida -U -f ''' + pkg + r''' -l ssl_bypass.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS SSL Pinning Bypass cargado");

    // --- TrustManager bypass ---
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.overload(
            "[Ljava.security.cert.X509Certificate;",
            "java.lang.String", "java.lang.String",
            "java.lang.String", "boolean",
            "[B").implementation = function(untrustedChain, authType, host, port, testing, ocspData) {
            console.log("[+] TrustManagerImpl.verifyChain bypassed para: " + host);
            return untrustedChain;
        };
    } catch(e) { console.log("[-] TrustManagerImpl no encontrado: " + e); }

    // --- X509TrustManager bypass ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "com.apkilis.TrustAllX509",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; },
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, TrustManagers, null);
        SSLContext.getInstance.overload("java.lang.String").implementation = function(protocol) {
            console.log("[+] SSLContext.getInstance interceptado: " + protocol);
            return sslCtx;
        };
    } catch(e) { console.log("[-] X509TrustManager bypass: " + e); }

    // --- OkHttp3 CertificatePinner bypass ---
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCerts) {
            console.log("[+] OkHttp3 CertificatePinner.check bypassed: " + hostname);
        };
    } catch(e) { console.log("[-] OkHttp3 no encontrado: " + e); }

    // --- OkHttp3 legacy check ---
    try {
        var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
        CertificatePinner2.check$okhttp.overload("java.lang.String",
            "kotlin.jvm.functions.Function0").implementation = function(hostname, fn) {
            console.log("[+] OkHttp3 check$okhttp bypassed: " + hostname);
        };
    } catch(e) {}

    // --- WebViewClient SSL error bypass ---
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] WebViewClient SSL error bypass");
            handler.proceed();
        };
    } catch(e) {}

    // --- HttpsURLConnection bypass ---
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier interceptado");
        };
    } catch(e) {}

    console.log("[*] SSL Pinning Bypass activo - intercepte trafico con Burp/Charles");
});
'''
        ssl_path = os.path.join(output_dir, "frida_ssl_bypass.js")
        with open(ssl_path, 'w') as f:
            f.write(ssl_bypass)
        scripts["ssl_bypass"] = ssl_path

        # 2. Root Detection Bypass
        root_bypass = r'''/* APKILIS - Root Detection Bypass
 * Bypasses: RootBeer, SafetyNet, common root checks
 * Uso: frida -U -f ''' + pkg + r''' -l root_bypass.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS Root Detection Bypass cargado");

    // --- RootBeer bypass ---
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() -> false");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        RootBeer.detectRootManagementApps.implementation = function() { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
        RootBeer.detectTestKeys.implementation = function() { return false; };
        RootBeer.checkForBusyBoxBinary.implementation = function() { return false; };
        RootBeer.checkForSuBinary.implementation = function() { return false; };
        RootBeer.checkSuExists.implementation = function() { return false; };
        RootBeer.checkForRWPaths.implementation = function() { return false; };
        RootBeer.checkForDangerousProps.implementation = function() { return false; };
        RootBeer.checkForRootNative.implementation = function() { return false; };
        RootBeer.detectRootCloakingApps.implementation = function() { return false; };
        RootBeer.isSelinuxFlagInEnabled.implementation = function() { return false; };
    } catch(e) { console.log("[-] RootBeer no encontrado"); }

    // --- File.exists bypass para paths de root ---
    try {
        var File = Java.use("java.io.File");
        var rootPaths = ["/system/app/Superuser.apk", "/system/xbin/su",
            "/system/bin/su", "/sbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/data/local/su", "/su/bin/su",
            "/.magisk", "/system/bin/.ext/.su"];
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    console.log("[+] File.exists blocked: " + path);
                    return false;
                }
            }
            return this.exists();
        };
    } catch(e) {}

    // --- Runtime.exec bypass para 'su', 'which su' ---
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
            var cmd_str = cmds.join(" ");
            if (cmd_str.indexOf("su") !== -1 || cmd_str.indexOf("which") !== -1) {
                console.log("[+] Runtime.exec blocked: " + cmd_str);
                throw Java.use("java.io.IOException").$new("Command not found");
            }
            return this.exec(cmds);
        };
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                console.log("[+] Runtime.exec blocked: " + cmd);
                throw Java.use("java.io.IOException").$new("Command not found");
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // --- Build.TAGS bypass ---
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        console.log("[+] Build.TAGS = release-keys");
    } catch(e) {}

    // --- SystemProperties bypass ---
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            if (key === "ro.debuggable" || key === "ro.secure") {
                console.log("[+] SystemProperties.get(" + key + ") -> spoofed");
                return key === "ro.debuggable" ? "0" : "1";
            }
            return this.get(key);
        };
    } catch(e) {}

    console.log("[*] Root Detection Bypass activo");
});
'''
        root_path = os.path.join(output_dir, "frida_root_bypass.js")
        with open(root_path, 'w') as f:
            f.write(root_bypass)
        scripts["root_bypass"] = root_path

        # 3. Anti-Frida/Anti-Debug Bypass
        anti_debug = r'''/* APKILIS - Anti-Debug & Anti-Frida Bypass
 * Uso: frida -U -f ''' + pkg + r''' -l anti_debug_bypass.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS Anti-Debug/Anti-Frida Bypass cargado");

    // --- ptrace anti-debug bypass ---
    try {
        Interceptor.attach(Module.findExportByName(null, "ptrace"), {
            onEnter: function(args) {
                this.request = args[0].toInt32();
                console.log("[+] ptrace(" + this.request + ") interceptado");
            },
            onLeave: function(retval) {
                if (this.request === 0) { // PTRACE_TRACEME
                    retval.replace(0);
                    console.log("[+] ptrace TRACEME -> 0 (bypass)");
                }
            }
        });
    } catch(e) {}

    // --- Anti-Frida: bloquear detección por puerto ---
    try {
        Interceptor.attach(Module.findExportByName(null, "connect"), {
            onEnter: function(args) {
                var sockaddr = args[1];
                var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                if (port === 27042 || port === 27043) {
                    console.log("[+] Anti-Frida: bloqueado connect al puerto " + port);
                    this.block = true;
                }
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(-1);
                }
            }
        });
    } catch(e) {}

    // --- Anti-Frida: hook open() para bloquear lectura de /proc/self/maps ---
    try {
        var openPtr = Module.findExportByName(null, "open");
        Interceptor.attach(openPtr, {
            onEnter: function(args) {
                this.path = args[0].readUtf8String();
                if (this.path && (this.path.indexOf("frida") !== -1 ||
                    this.path.indexOf("xposed") !== -1 ||
                    this.path.indexOf("substrate") !== -1)) {
                    console.log("[+] Anti-Frida: blocked open(" + this.path + ")");
                    this.block = true;
                }
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(-1);
                }
            }
        });
    } catch(e) {}

    // --- strstr hook para bloquear detección de "frida" en strings ---
    try {
        Interceptor.attach(Module.findExportByName(null, "strstr"), {
            onEnter: function(args) {
                this.haystack = args[0];
                this.needle = args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.needle && (this.needle.indexOf("frida") !== -1 ||
                    this.needle.indexOf("LIBFRIDA") !== -1 ||
                    this.needle.indexOf("gadget") !== -1)) {
                    console.log("[+] Anti-Frida: strstr('" + this.needle + "') -> NULL");
                    retval.replace(ptr(0));
                }
            }
        });
    } catch(e) {}

    // --- Debug.isDebuggerConnected bypass ---
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] Debug.isDebuggerConnected() -> false");
            return false;
        };
    } catch(e) {}

    console.log("[*] Anti-Debug/Anti-Frida Bypass activo");
});
'''
        anti_debug_path = os.path.join(output_dir, "frida_anti_debug_bypass.js")
        with open(anti_debug_path, 'w') as f:
            f.write(anti_debug)
        scripts["anti_debug_bypass"] = anti_debug_path

        # 4. Crypto Hooks (interceptar operaciones criptográficas)
        crypto_hooks = r'''/* APKILIS - Crypto Interceptor
 * Intercepta: AES, RSA, HMAC, MessageDigest, SecretKeySpec
 * Uso: frida -U -f ''' + pkg + r''' -l crypto_hooks.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS Crypto Interceptor cargado");

    // --- Cipher (AES, RSA, DES, etc.) ---
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            console.log("\n[CRYPTO] Cipher.getInstance: " + transformation);
            return this.getInstance(transformation);
        };
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[CRYPTO] Cipher.doFinal input (" + input.length + " bytes):");
            console.log("  HEX: " + bytesToHex(input).substring(0, 128));
            var result = this.doFinal(input);
            console.log("[CRYPTO] Cipher.doFinal output (" + result.length + " bytes):");
            console.log("  HEX: " + bytesToHex(result).substring(0, 128));
            return result;
        };
    } catch(e) { console.log("[-] Cipher hook: " + e); }

    // --- SecretKeySpec (clave AES/HMAC) ---
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algo) {
            console.log("\n[CRYPTO] SecretKeySpec: " + algo);
            console.log("  KEY HEX: " + bytesToHex(keyBytes));
            console.log("  KEY UTF8: " + bytesToString(keyBytes));
            return this.$init(keyBytes, algo);
        };
    } catch(e) {}

    // --- IvParameterSpec (IV para AES-CBC) ---
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B").implementation = function(iv) {
            console.log("[CRYPTO] IvParameterSpec:");
            console.log("  IV HEX: " + bytesToHex(iv));
            return this.$init(iv);
        };
    } catch(e) {}

    // --- MessageDigest (MD5, SHA-1, SHA-256) ---
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function(algo) {
            console.log("[CRYPTO] MessageDigest: " + algo);
            return this.getInstance(algo);
        };
        MessageDigest.digest.overload("[B").implementation = function(input) {
            var result = this.digest(input);
            console.log("[CRYPTO] MessageDigest.digest:");
            console.log("  INPUT: " + bytesToString(input).substring(0, 64));
            console.log("  HASH:  " + bytesToHex(result));
            return result;
        };
    } catch(e) {}

    // --- Mac (HMAC) ---
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.getInstance.overload("java.lang.String").implementation = function(algo) {
            console.log("[CRYPTO] Mac.getInstance: " + algo);
            return this.getInstance(algo);
        };
        Mac.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            console.log("[CRYPTO] HMAC result: " + bytesToHex(result));
            return result;
        };
    } catch(e) {}

    // --- KeyStore ---
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload("java.io.InputStream", "[C").implementation = function(stream, password) {
            if (password) {
                console.log("[CRYPTO] KeyStore.load password: " + charArrayToString(password));
            }
            return this.load(stream, password);
        };
    } catch(e) {}

    // --- Base64 (posible ofuscación de datos) ---
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            var result = this.decode(str, flags);
            if (str.length > 20) {
                console.log("[CRYPTO] Base64.decode: " + str.substring(0, 80) + "...");
                console.log("  DECODED: " + bytesToString(result).substring(0, 80));
            }
            return result;
        };
    } catch(e) {}

    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length && i < 64; i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            hex += (b.length === 1 ? "0" : "") + b;
        }
        return hex;
    }
    function bytesToString(bytes) {
        try {
            var String = Java.use("java.lang.String");
            return String.$new(bytes, "UTF-8");
        } catch(e) { return "(binary)"; }
    }
    function charArrayToString(chars) {
        var s = "";
        for (var i = 0; i < chars.length; i++) s += String.fromCharCode(chars[i]);
        return s;
    }

    console.log("[*] Crypto Interceptor activo - todas las operaciones cripto seran logueadas");
});
'''
        crypto_path = os.path.join(output_dir, "frida_crypto_hooks.js")
        with open(crypto_path, 'w') as f:
            f.write(crypto_hooks)
        scripts["crypto_hooks"] = crypto_path

        # 5. Network Traffic Monitor
        network_monitor = r'''/* APKILIS - Network Traffic Monitor
 * Intercepta: HTTP/HTTPS requests, WebSocket, DNS
 * Uso: frida -U -f ''' + pkg + r''' -l network_monitor.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS Network Traffic Monitor cargado");

    // --- HttpURLConnection ---
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            console.log("\n[NET] URL.openConnection: " + url);
            return this.openConnection();
        };
    } catch(e) {}

    // --- OkHttp3 Interceptor ---
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.execute.implementation = function() {
            var req = this.request();
            console.log("\n[NET] OkHttp3 " + req.method() + " " + req.url().toString());
            var headers = req.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log("  " + headers.name(i) + ": " + headers.value(i));
            }
            var response = this.execute();
            console.log("[NET] Response: " + response.code() + " " + response.message());
            return response;
        };
    } catch(e) {}

    // --- WebView.loadUrl ---
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
            console.log("[NET] WebView.loadUrl: " + url);
            return this.loadUrl(url);
        };
    } catch(e) {}

    // --- SharedPreferences monitoring ---
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SharedPreferencesImpl.putString.implementation = function(key, value) {
            console.log("[DATA] SharedPreferences.putString: " + key + " = " +
                (value ? value.substring(0, 80) : "null"));
            return this.putString(key, value);
        };
    } catch(e) {}

    console.log("[*] Network Traffic Monitor activo");
});
'''
        net_path = os.path.join(output_dir, "frida_network_monitor.js")
        with open(net_path, 'w') as f:
            f.write(network_monitor)
        scripts["network_monitor"] = net_path

        # 6. Method Tracer (configurable por paquete)
        method_tracer = r'''/* APKILIS - Dynamic Method Tracer
 * Traza todas las llamadas a métodos de clases del paquete objetivo
 * Uso: frida -U -f ''' + pkg + r''' -l method_tracer.js --no-pause
 *
 * CONFIGURABLE: Cambie TARGET_PACKAGE para rastrear otro paquete
 */
var TARGET_PACKAGE = "''' + pkg + r'''";
var MAX_DEPTH = 3;
var callCount = 0;

Java.perform(function() {
    console.log("[*] APKILIS Method Tracer para: " + TARGET_PACKAGE);
    console.log("[*] Enumerando clases...");

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith(TARGET_PACKAGE)) {
                try {
                    var clazz = Java.use(className);
                    var methods = clazz.class.getDeclaredMethods();
                    for (var i = 0; i < methods.length; i++) {
                        var methodName = methods[i].getName();
                        hookMethod(className, methodName);
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("[*] Enumeración completada. Esperando llamadas...");
        }
    });

    function hookMethod(className, methodName) {
        try {
            var clazz = Java.use(className);
            var overloads = clazz[methodName].overloads;
            for (var i = 0; i < overloads.length; i++) {
                overloads[i].implementation = function() {
                    callCount++;
                    var shortClass = this.$className.split(".").pop();
                    console.log("[TRACE #" + callCount + "] " + shortClass + "." + methodName + "()");
                    if (arguments.length > 0) {
                        for (var a = 0; a < arguments.length && a < 3; a++) {
                            try {
                                console.log("  arg[" + a + "] = " + String(arguments[a]).substring(0, 80));
                            } catch(e) {}
                        }
                    }
                    return this[methodName].apply(this, arguments);
                };
            }
        } catch(e) {}
    }
});
'''
        tracer_path = os.path.join(output_dir, "frida_method_tracer.js")
        with open(tracer_path, 'w') as f:
            f.write(method_tracer)
        scripts["method_tracer"] = tracer_path

        # 7. Activity/Intent Monitor
        intent_monitor = r'''/* APKILIS - Activity & Intent Monitor
 * Intercepta: startActivity, sendBroadcast, startService, ContentResolver
 * Uso: frida -U -f ''' + pkg + r''' -l intent_monitor.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS Activity & Intent Monitor cargado");

    // --- startActivity ---
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
            console.log("\n[INTENT] startActivity:");
            dumpIntent(intent);
            return this.startActivity(intent);
        };
        Activity.startActivityForResult.overload("android.content.Intent", "int")
            .implementation = function(intent, code) {
            console.log("\n[INTENT] startActivityForResult (code=" + code + "):");
            dumpIntent(intent);
            return this.startActivityForResult(intent, code);
        };
    } catch(e) {}

    // --- sendBroadcast ---
    try {
        var Context = Java.use("android.content.ContextWrapper");
        Context.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
            console.log("\n[INTENT] sendBroadcast:");
            dumpIntent(intent);
            return this.sendBroadcast(intent);
        };
    } catch(e) {}

    // --- startService ---
    try {
        var Context2 = Java.use("android.content.ContextWrapper");
        Context2.startService.overload("android.content.Intent").implementation = function(intent) {
            console.log("\n[INTENT] startService:");
            dumpIntent(intent);
            return this.startService(intent);
        };
    } catch(e) {}

    // --- ContentResolver.query ---
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;",
            "java.lang.String", "[Ljava.lang.String;", "java.lang.String"
        ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            console.log("[DATA] ContentResolver.query: " + uri.toString());
            if (selection) console.log("  WHERE: " + selection);
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch(e) {}

    function dumpIntent(intent) {
        try {
            console.log("  Action: " + intent.getAction());
            console.log("  Component: " + intent.getComponent());
            console.log("  Data: " + intent.getDataString());
            console.log("  Type: " + intent.getType());
            console.log("  Flags: 0x" + intent.getFlags().toString(16));
            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet().iterator();
                while (keys.hasNext()) {
                    var key = keys.next();
                    console.log("  Extra: " + key + " = " + extras.get(key));
                }
            }
        } catch(e) {}
    }

    console.log("[*] Activity & Intent Monitor activo");
});
'''
        intent_path = os.path.join(output_dir, "frida_intent_monitor.js")
        with open(intent_path, 'w') as f:
            f.write(intent_monitor)
        scripts["intent_monitor"] = intent_path

        # 8. Emulator Detection Bypass
        emu_bypass = r'''/* APKILIS - Emulator Detection Bypass
 * Uso: frida -U -f ''' + pkg + r''' -l emulator_bypass.js --no-pause
 */
Java.perform(function() {
    console.log("[*] APKILIS Emulator Detection Bypass cargado");

    try {
        var Build = Java.use("android.os.Build");
        Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
        Build.MODEL.value = "Pixel 2";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.DEVICE.value = "walleye";
        Build.PRODUCT.value = "walleye";
        Build.HARDWARE.value = "walleye";
        Build.BOARD.value = "walleye";
        Build.TAGS.value = "release-keys";
        Build.HOST.value = "wphr1.hot.corp.google.com";
        console.log("[+] Build properties spoofed (Pixel 2)");
    } catch(e) {}

    // --- TelephonyManager spoof ---
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log("[+] TelephonyManager.getDeviceId spoofed");
            return "351756061523999";
        };
        TelephonyManager.getSubscriberId.implementation = function() {
            return "310260000000000";
        };
        TelephonyManager.getLine1Number.implementation = function() {
            return "+15551234567";
        };
        TelephonyManager.getNetworkOperatorName.implementation = function() {
            return "T-Mobile";
        };
        TelephonyManager.getSimOperatorName.implementation = function() {
            return "T-Mobile";
        };
    } catch(e) {}

    // --- Sensor spoof (emuladores no tienen ciertos sensores) ---
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        SensorManager.getSensorList.implementation = function(type) {
            var list = this.getSensorList(type);
            console.log("[+] SensorManager.getSensorList(" + type + ") = " + list.size() + " sensors");
            return list;
        };
    } catch(e) {}

    console.log("[*] Emulator Detection Bypass activo");
});
'''
        emu_path = os.path.join(output_dir, "frida_emulator_bypass.js")
        with open(emu_path, 'w') as f:
            f.write(emu_bypass)
        scripts["emulator_bypass"] = emu_path

        return scripts

    # ----------------------------------------------------------------
    # ADB COMMANDS
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_adb_commands(pkg, main_activity, apk_path):
        cmds = []
        cmds.append({
            "category": "Instalación",
            "commands": [
                f"adb install -r {os.path.basename(apk_path)}",
                f"adb install-multiple *.apk  # Para split APKs",
            ]
        })
        cmds.append({
            "category": "Lanzamiento y Depuración",
            "commands": [
                f"adb shell am start -n {pkg}/{main_activity}" if main_activity else f"adb shell monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
                f"adb shell am force-stop {pkg}",
                f"adb shell pm clear {pkg}",
                f"adb shell am start -D -n {pkg}/{main_activity}  # Debug mode" if main_activity else "",
            ]
        })
        cmds.append({
            "category": "Información del Paquete",
            "commands": [
                f"adb shell dumpsys package {pkg}",
                f"adb shell pm path {pkg}",
                f"adb shell pm dump {pkg} | grep -i 'version\\|permission\\|flag'",
                f"adb shell dumpsys activity activities | grep {pkg}",
                f"adb shell cat /data/system/packages.xml | grep {pkg}",
            ]
        })
        cmds.append({
            "category": "Extracción de Datos Forenses",
            "commands": [
                f"adb shell run-as {pkg} ls -la /data/data/{pkg}/",
                f"adb shell run-as {pkg} ls -la /data/data/{pkg}/shared_prefs/",
                f"adb shell run-as {pkg} cat /data/data/{pkg}/shared_prefs/*.xml",
                f"adb shell run-as {pkg} ls -la /data/data/{pkg}/databases/",
                f"adb shell run-as {pkg} ls -la /data/data/{pkg}/files/",
                f"adb shell run-as {pkg} ls -la /data/data/{pkg}/cache/",
                f"# Copiar bases de datos:",
                f"adb shell run-as {pkg} cp /data/data/{pkg}/databases/*.db /sdcard/",
                f"adb pull /sdcard/*.db ./forensic_data/",
            ]
        })
        cmds.append({
            "category": "Logcat y Runtime",
            "commands": [
                f"adb logcat --pid=$(adb shell pidof {pkg}) -v time",
                f"adb logcat | grep -iE '{pkg}|error|exception|crash|fatal'",
                f"adb shell dumpsys meminfo {pkg}",
                f"adb shell dumpsys activity top | head -50",
                f"adb shell ps -A | grep {pkg}",
                f"adb shell cat /proc/$(adb shell pidof {pkg})/maps | grep -v '\\[' | head -30",
            ]
        })
        cmds.append({
            "category": "Red y Tráfico",
            "commands": [
                f"adb shell settings put global http_proxy <BURP_IP>:8080",
                f"adb shell settings put global http_proxy :0  # Quitar proxy",
                f"adb shell dumpsys connectivity | grep -i 'proxy\\|network'",
                f"adb shell netstat -tlnp | grep {pkg}",
                f"adb shell cat /proc/net/tcp",
                f"# Captura de tráfico:",
                f"adb shell tcpdump -i any -w /sdcard/capture.pcap &",
                f"adb pull /sdcard/capture.pcap ./forensic_data/",
            ]
        })
        cmds.append({
            "category": "Screenshot y Grabación",
            "commands": [
                f"adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png",
                f"adb shell screenrecord /sdcard/recording.mp4 --time-limit 30",
                f"adb pull /sdcard/recording.mp4",
            ]
        })
        # Filter empty commands
        for cat in cmds:
            cat["commands"] = [c for c in cat["commands"] if c]
        return cmds

    # ----------------------------------------------------------------
    # DROZER COMMANDS
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_drozer_commands(pkg, manifest):
        cmds = []
        cmds.append({
            "category": "Reconocimiento",
            "commands": [
                f"run app.package.info -a {pkg}",
                f"run app.package.attacksurface {pkg}",
                f"run app.package.manifest {pkg}",
            ]
        })

        exported = manifest.get("exported_components", [])
        activities = [c for c in exported if c.get("type") == "activity"]
        services = [c for c in exported if c.get("type") == "service"]
        receivers = [c for c in exported if c.get("type") == "receiver"]
        providers = [c for c in exported if c.get("type") == "provider"]

        if activities:
            act_cmds = [f"run app.activity.info -a {pkg}"]
            for act in activities[:5]:
                act_cmds.append(f"run app.activity.start --component {pkg} {act['name']}")
            cmds.append({"category": f"Activities Exportadas ({len(activities)})", "commands": act_cmds})

        if services:
            svc_cmds = [f"run app.service.info -a {pkg}"]
            for svc in services[:5]:
                svc_cmds.append(f"run app.service.start --component {pkg} {svc['name']}")
                svc_cmds.append(f"run app.service.send {pkg} {svc['name']} --msg 1 0 0")
            cmds.append({"category": f"Services Exportados ({len(services)})", "commands": svc_cmds})

        if receivers:
            rec_cmds = [f"run app.broadcast.info -a {pkg}"]
            for rec in receivers[:5]:
                rec_cmds.append(f"run app.broadcast.send --component {pkg} {rec['name']} --action {rec['name']}")
            cmds.append({"category": f"Receivers Exportados ({len(receivers)})", "commands": rec_cmds})

        if providers:
            prov_cmds = [
                f"run app.provider.info -a {pkg}",
                f"run app.provider.finduri {pkg}",
                f"run scanner.provider.injection -a {pkg}",
                f"run scanner.provider.traversal -a {pkg}",
            ]
            for prov in providers[:3]:
                prov_cmds.append(f"run app.provider.query content://{pkg}.provider/ --projection '*'")
            cmds.append({"category": f"Providers Exportados ({len(providers)})", "commands": prov_cmds})

        cmds.append({
            "category": "Scanners de Vulnerabilidades",
            "commands": [
                f"run scanner.activity.browsable -a {pkg}",
                f"run scanner.misc.native -a {pkg}",
                f"run scanner.misc.readablefiles -a {pkg}",
                f"run scanner.misc.writablefiles -a {pkg}",
                f"run scanner.misc.secretcodes -a {pkg}",
            ]
        })

        return cmds

    # ----------------------------------------------------------------
    # OBJECTION COMMANDS
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_objection_commands(pkg):
        return [
            {"category": "Inicio y Exploración", "commands": [
                f"objection -g {pkg} explore",
                "env",
                "android hooking list activities",
                "android hooking list services",
                "android hooking list receivers",
                "android hooking list classes",
            ]},
            {"category": "SSL Pinning & Root", "commands": [
                "android sslpinning disable",
                "android root disable",
                "android root simulate",
            ]},
            {"category": "Hooking", "commands": [
                f"android hooking watch class {pkg}.MainActivity",
                f"android hooking search classes {pkg}",
                "android hooking watch class_method javax.crypto.Cipher.doFinal --dump-args --dump-return --dump-backtrace",
                "android hooking watch class_method javax.crypto.spec.SecretKeySpec.$init --dump-args --dump-backtrace",
                "android hooking watch class_method java.net.URL.openConnection --dump-args --dump-return",
            ]},
            {"category": "Keychain & Storage", "commands": [
                "android keystore list",
                "android keystore clear",
                "android clipboard monitor",
                "sqlite connect /data/data/{}/databases/*.db".format(pkg),
            ]},
            {"category": "Memoria & Filesystem", "commands": [
                "memory list modules",
                "memory list exports libnative-lib.so",
                "memory dump all memoria_dump.bin",
                "memory search 'password' --string",
                "memory search 'token' --string",
                "android heap search instances java.lang.String --query 'password\\|token\\|secret\\|key'",
            ]},
            {"category": "Intent Injection", "commands": [
                f"android intent launch_activity {pkg}/.MainActivity",
                "android intent launch_service --action android.intent.action.MAIN",
            ]},
        ]

    # ----------------------------------------------------------------
    # PROXY CONFIG
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_proxy_config(pkg):
        return {
            "burp_suite": {
                "description": "Configuración para Burp Suite",
                "steps": [
                    "1. Configurar Burp en Proxy > Options > Add listener (0.0.0.0:8080)",
                    "2. Exportar certificado: Proxy > Options > Import/export CA cert > Certificate in DER format",
                    "3. Convertir cert: openssl x509 -inform DER -in burp.der -out burp.pem",
                    "4. Instalar en device: adb push burp.pem /sdcard/ → Settings > Security > Install from storage",
                    "5. Configurar proxy: adb shell settings put global http_proxy <PC_IP>:8080",
                    f"6. Lanzar con Frida: frida -U -f {pkg} -l frida_ssl_bypass.js --no-pause",
                    "7. Quitar proxy: adb shell settings put global http_proxy :0",
                ],
            },
            "charles_proxy": {
                "description": "Configuración para Charles Proxy",
                "steps": [
                    "1. Charles > Proxy > Proxy Settings > Port 8888",
                    "2. Charles > Help > SSL Proxying > Install Charles Root Certificate on a Mobile Device",
                    "3. Agregar SSL Proxying: Proxy > SSL Proxying Settings > Add (*:*)",
                    f"4. Lanzar con Frida: frida -U -f {pkg} -l frida_ssl_bypass.js --no-pause",
                ],
            },
            "mitmproxy": {
                "description": "Configuración para mitmproxy",
                "steps": [
                    "1. Iniciar: mitmproxy --mode regular --listen-port 8080 --set block_global=false",
                    "2. Instalar cert: adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/",
                    "3. Configurar proxy: adb shell settings put global http_proxy <PC_IP>:8080",
                    f"4. Lanzar con Frida: frida -U -f {pkg} -l frida_ssl_bypass.js --no-pause",
                    "5. Ver tráfico: mitmweb --listen-port 8080 --web-port 8081",
                ],
            },
        }

    # ----------------------------------------------------------------
    # MEMORY DUMP COMMANDS
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_memory_commands(pkg):
        return [
            {"tool": "Frida Memory Scanner", "commands": [
                f"frida -U -n {pkg} -e 'Process.enumerateModules()'",
                f"frida -U -n {pkg} -e 'Memory.scan(ptr(\"0x0\"), 0x7fffffffffff, \"password\", {{ onMatch: function(addr){{ console.log(addr); }} }})'",
            ]},
            {"tool": "Objection Memory Dump", "commands": [
                f"objection -g {pkg} explore",
                "memory dump all /tmp/memdump.bin",
                "memory list modules",
                "# Luego buscar strings: strings /tmp/memdump.bin | grep -iE 'password|token|secret|key|jwt'",
            ]},
            {"tool": "Fridump", "commands": [
                f"python fridump.py -U -s {pkg}",
                "# Buscar en dumps: grep -rn 'password\\|token\\|api_key' dump/",
            ]},
            {"tool": "ADB Memory", "commands": [
                f"adb shell dumpsys meminfo {pkg}",
                f"adb shell am dumpheap {pkg} /sdcard/heap.hprof",
                "adb pull /sdcard/heap.hprof",
                "# Analizar con: Eclipse MAT o jhat heap.hprof",
            ]},
        ]

    # ----------------------------------------------------------------
    # RUNTIME HOOKS SUMMARY
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_runtime_hooks(pkg, manifest, structure):
        hooks = []

        # Hooks basados en permisos
        perms = manifest.get("permissions", [])
        if "android.permission.CAMERA" in perms:
            hooks.append({
                "target": "Camera API",
                "frida_cmd": f"frida -U -f {pkg} -e 'Java.perform(function(){{var cam=Java.use(\"android.hardware.Camera\");cam.open.implementation=function(){{console.log(\"[CAM] Camera.open()\");return this.open.apply(this,arguments);}};}})'",
                "reason": "App solicita permiso de CAMERA",
            })
        if "android.permission.RECORD_AUDIO" in perms:
            hooks.append({
                "target": "Audio Recording",
                "frida_cmd": f"frida -U -f {pkg} -e 'Java.perform(function(){{var mr=Java.use(\"android.media.MediaRecorder\");mr.start.implementation=function(){{console.log(\"[AUDIO] MediaRecorder.start()\");return this.start();}};}})'",
                "reason": "App solicita permiso RECORD_AUDIO",
            })
        if any("SMS" in p for p in perms):
            hooks.append({
                "target": "SMS Manager",
                "frida_cmd": f"frida -U -f {pkg} -e 'Java.perform(function(){{var sms=Java.use(\"android.telephony.SmsManager\");sms.sendTextMessage.implementation=function(dest,sc,text,pi,di){{console.log(\"[SMS] sendTextMessage: \"+dest+\" -> \"+text);return this.sendTextMessage(dest,sc,text,pi,di);}};}})'",
                "reason": "App solicita permisos SMS",
            })
        if any("LOCATION" in p for p in perms):
            hooks.append({
                "target": "Location Manager",
                "frida_cmd": f"frida -U -f {pkg} -e 'Java.perform(function(){{var lm=Java.use(\"android.location.LocationManager\");lm.getLastKnownLocation.implementation=function(p){{console.log(\"[LOC] getLastKnownLocation(\"+p+\")\");return this.getLastKnownLocation(p);}};}})'",
                "reason": "App solicita permisos de ubicación",
            })

        # Hooks basados en libs nativas
        if structure and structure.get("native_libs"):
            for lib in structure.get("native_libs", [])[:3]:
                lib_name = lib.get("name", "")
                hooks.append({
                    "target": f"Native Library: {lib_name}",
                    "frida_cmd": f"frida -U -f {pkg} -e 'var mod=Process.findModuleByName(\"{lib_name}\");if(mod){{console.log(\"[NATIVE] \"+mod.name+\" base: \"+mod.base+\" size: \"+mod.size);Module.enumerateExports(mod.name,{{onMatch:function(exp){{console.log(\"  export: \"+exp.name);}},onComplete:function(){{}}}});}}'",
                    "reason": f"Librería nativa detectada: {lib_name}",
                })

        return hooks

    # ----------------------------------------------------------------
    # MASTER README
    # ----------------------------------------------------------------

    @staticmethod
    def _gen_master_readme(path, pkg, main_activity, result):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# 🔬 APKILIS v{VERSION} - Kit de Análisis Dinámico\n\n")
            f.write(f"**Paquete objetivo:** `{pkg}`\n")
            f.write(f"**Actividad principal:** `{main_activity}`\n")
            f.write(f"**Generado:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## 📋 Prerequisitos\n\n")
            f.write("```bash\n")
            f.write("# Instalar Frida\n")
            f.write("pip install frida-tools frida\n\n")
            f.write("# Instalar Objection\n")
            f.write("pip install objection\n\n")
            f.write("# Frida-server en el dispositivo (match version!)\n")
            f.write("# Descargar de: https://github.com/frida/frida/releases\n")
            f.write("adb push frida-server-XX.X.X-android-arm64 /data/local/tmp/frida-server\n")
            f.write("adb shell chmod 755 /data/local/tmp/frida-server\n")
            f.write("adb shell /data/local/tmp/frida-server &\n")
            f.write("```\n\n")

            f.write("## 🗂️ Scripts Generados\n\n")
            f.write("| Script | Descripción | Uso |\n|---|---|---|\n")
            for name, spath in result.get("frida_scripts", {}).items():
                fname = os.path.basename(spath)
                f.write(f"| `{fname}` | {name.replace('_', ' ').title()} | `frida -U -f {pkg} -l {fname} --no-pause` |\n")
            f.write("\n")

            f.write("## 🔧 Comandos ADB\n\n")
            for cat in result.get("adb_commands", []):
                f.write(f"### {cat['category']}\n```bash\n")
                for cmd in cat["commands"]:
                    f.write(f"{cmd}\n")
                f.write("```\n\n")

            f.write("## 🐉 Drozer\n\n")
            f.write("```bash\n# Iniciar Drozer\ndrozer console connect\n```\n\n")
            for cat in result.get("drozer_commands", []):
                f.write(f"### {cat['category']}\n```\n")
                for cmd in cat["commands"]:
                    f.write(f"dz> {cmd}\n")
                f.write("```\n\n")

            f.write("## 🎯 Objection\n\n")
            for cat in result.get("objection_commands", []):
                f.write(f"### {cat['category']}\n```\n")
                for cmd in cat["commands"]:
                    f.write(f"{cmd}\n")
                f.write("```\n\n")

            f.write("## 🌐 Configuración de Proxy\n\n")
            for name, config in result.get("proxy_config", {}).items():
                f.write(f"### {config['description']}\n")
                for step in config["steps"]:
                    f.write(f"- {step}\n")
                f.write("\n")

            f.write("## 💾 Memory Dump\n\n")
            for cat in result.get("memory_dump_commands", []):
                f.write(f"### {cat['tool']}\n```bash\n")
                for cmd in cat["commands"]:
                    f.write(f"{cmd}\n")
                f.write("```\n\n")

            if result.get("runtime_hooks"):
                f.write("## 🎣 Runtime Hooks Recomendados\n\n")
                for hook in result["runtime_hooks"]:
                    f.write(f"### {hook['target']}\n")
                    f.write(f"**Razón:** {hook['reason']}\n")
                    f.write(f"```bash\n{hook['frida_cmd']}\n```\n\n")

            f.write("---\n")
            f.write(f"*Generado por APKILIS v{VERSION} - APKForensicMaster Ultra*\n")



class GameAntiCheatAnalyzer:
    """Detects game anti-cheat systems, memory protections, asset encryption
    and generates bypass techniques.  Pure static analysis."""

    # ── Anti-cheat signature database ──────────────────────────────────
    ANTICHEAT_SIGNATURES = {
        "Unity Anti-Cheat": {
            "strings": ["UnityAntiCheat", "com.unity.anticheat"],
            "libs": [],
            "bypass_difficulty": "medium",
        },
        "BattlEye": {
            "strings": ["BEClient", "BEService", "BattlEye"],
            "libs": ["libBEClient.so"],
            "bypass_difficulty": "very_hard",
        },
        "EasyAntiCheat (EAC)": {
            "strings": ["EasyAntiCheat", "easyanticheat"],
            "libs": ["libEAC.so"],
            "bypass_difficulty": "very_hard",
        },
        "Denuvo Anti-Cheat": {
            "strings": ["denuvo", "Denuvo"],
            "libs": [],
            "bypass_difficulty": "extremely_hard",
        },
        "GameGuard (nProtect)": {
            "strings": ["GameGuard", "nProtect", "npgg.des", "GameMon"],
            "libs": [],
            "bypass_difficulty": "hard",
        },
        "Tencent Anti-Cheat (ACE)": {
            "strings": ["TssSDK", "com.tencent.tp", "AntiCheatExpert"],
            "libs": ["libtersafe.so"],
            "bypass_difficulty": "hard",
        },
        "NetEase Anti-Cheat": {
            "strings": ["com.netease.anticheat"],
            "libs": ["libneprotect.so"],
            "bypass_difficulty": "hard",
        },
        "miHoYo Anti-Cheat": {
            "strings": ["mhyprot", "libmhyprot.so"],
            "libs": ["libmhyprot.so"],
            "bypass_difficulty": "very_hard",
        },
    }

    # ── Memory-protection indicators ──────────────────────────────────
    MEMORY_PROTECTION_PATTERNS = {
        "proc_maps_monitoring": {
            "strings": ["/proc/self/maps", "inotify_add_watch"],
            "type": "Memory scan countermeasure",
            "bypass": "Hook open()/read() to hide /proc/self/maps entries",
        },
        "ptrace_antidebug": {
            "strings": ["PTRACE_TRACEME", "TracerPid", "ptrace"],
            "type": "Anti-debug (ptrace)",
            "bypass": "Hook ptrace() to return 0; patch TracerPid reads",
        },
        "value_encryption": {
            "strings": ["EncryptedPreferences", "EncryptedInt", "EncryptedFloat",
                         "ObfuscatedValue"],
            "type": "Value encryption in memory",
            "bypass": "Hook encryption/decryption wrappers to read plain values",
        },
        "speed_hack_detection": {
            "strings": ["SystemClock", "System.nanoTime", "elapsedRealtime",
                         "uptimeMillis", "TimeIntegrity"],
            "type": "Speed-hack detection",
            "bypass": "Hook SystemClock.elapsedRealtime / System.nanoTime to return consistent values",
        },
        "cheat_tool_detection": {
            "strings": ["GameGuardian", "Cheat Engine", "Lucky Patcher",
                         "Freedom", "iGG", "SBGameHacker", "CreeHack"],
            "type": "Cheat-tool package detection",
            "bypass": "Hook PackageManager.getInstalledPackages to filter cheat apps",
        },
    }

    # ── Game-engine RE tool commands ──────────────────────────────────
    ENGINE_RE_COMMANDS = {
        "Unity": {
            "markers": ["libunity.so", "libil2cpp.so", "assets/bin/Data",
                         "UnityEngine", "globalgamemanagers"],
            "commands": [
                {"tool": "AssetStudio", "cmd": "AssetStudioCLI <apk_or_assets_dir>",
                 "purpose": "Extract & preview Unity assets (textures, meshes, audio)"},
                {"tool": "UABE", "cmd": "UABE openBundleFile <bundle_path>",
                 "purpose": "Edit Unity Asset Bundles (modify game data)"},
                {"tool": "AssetRipper", "cmd": "AssetRipper <game_data_dir> -o <output>",
                 "purpose": "Full project reconstruction from Unity assets"},
            ],
        },
        "IL2CPP": {
            "markers": ["libil2cpp.so", "global-metadata.dat"],
            "commands": [
                {"tool": "Il2CppDumper", "cmd": "Il2CppDumper libil2cpp.so global-metadata.dat <output>",
                 "purpose": "Dump IL2CPP metadata, reconstruct C# headers"},
                {"tool": "Il2CppInspector", "cmd": "Il2CppInspector -i libil2cpp.so -m global-metadata.dat -o <output>",
                 "purpose": "Generate IDA/Ghidra scripts + C# stubs from IL2CPP"},
                {"tool": "Cpp2IL", "cmd": "Cpp2IL --game-path <dir> --exe-name libil2cpp.so",
                 "purpose": "Reconstruct managed assemblies from IL2CPP binary"},
            ],
        },
        "Unreal Engine": {
            "markers": ["libUE4.so", "libUnreal.so", ".pak", "UE4Game"],
            "commands": [
                {"tool": "UModel", "cmd": "umodel -export -all -game=ue4 <pak_file>",
                 "purpose": "Export UE4/5 assets (meshes, textures, animations)"},
                {"tool": "FModel", "cmd": "FModel  # GUI - open .pak file",
                 "purpose": "Browse & export Unreal PAK archives"},
                {"tool": "UnrealPakTool", "cmd": "UnrealPak <pak_file> -Extract <output_dir>",
                 "purpose": "Extract raw files from UE PAK containers"},
            ],
        },
        "Cocos2d": {
            "markers": ["libcocos2d", "cocos2d", "cocos2dx"],
            "commands": [
                {"tool": "Cocos2d resource extractor",
                 "cmd": "# Extract Cocos2d .plist / .csb / .ccbi resources from assets/",
                 "purpose": "Decode sprite sheets and scene files"},
                {"tool": "TexturePacker (reverse)",
                 "cmd": "TextureUnpacker <plist_file> <png_file>",
                 "purpose": "Split packed sprite sheets back into individual images"},
            ],
        },
    }

    # ── Wallhack / ESP / Aimbot countermeasure strings ────────────────
    EXPLOIT_SURFACE_PATTERNS = {
        "shader_modification": {
            "strings": ["GL_FRAGMENT_SHADER", "GL_VERTEX_SHADER", "glShaderSource",
                         "ShaderLab", "custom/shader"],
            "type": "Shader modification (wallhack)",
        },
        "coordinate_access": {
            "strings": ["Transform.position", "Camera.main", "RenderPipeline",
                         "WorldToScreenPoint", "localPosition"],
            "type": "Coordinate system access (ESP)",
        },
        "input_injection": {
            "strings": ["MotionEvent", "InputEvent", "dispatchTouchEvent",
                         "InputManager", "injectInputEvent"],
            "type": "Input injection (aimbot / auto-tap)",
        },
    }

    # ── Asset-protection patterns ─────────────────────────────────────
    ASSET_PROTECTION_PATTERNS = {
        "encrypted_assets": {
            "strings": ["AssetDecrypt", "DecryptAsset", "XorDecrypt",
                         "AES/CBC", "AssetEncryption"],
            "type": "Encrypted game assets",
            "extraction": "Identify decryption routine; hook or replicate key + IV",
        },
        "asset_bundle_protection": {
            "strings": ["EncryptedAssetBundle", "BundleEncrypt",
                         "CustomAssetBundleLoader"],
            "type": "Unity AssetBundle encryption",
            "extraction": "Hook AssetBundle.LoadFromFile to intercept decrypted bundles",
        },
        "pak_encryption": {
            "strings": ["PakEncryption", "FPakFile", "EncryptionKeyGuid"],
            "type": "Unreal PAK encryption",
            "extraction": "Extract AES key from binary; decrypt with UnrealPakTool -aes=<key>",
        },
        "save_encryption": {
            "strings": ["EncryptedSave", "SaveEncryption", "CloudSaveIntegrity",
                         "PlayerPrefs", "EncryptedPlayerPrefs"],
            "type": "Save-game / PlayerPrefs encryption",
            "extraction": "Hook save read/write to capture plaintext; replicate cipher offline",
        },
    }

    # ── Frida bypass script templates ─────────────────────────────────
    FRIDA_BYPASS_SCRIPTS = {
        "memory_scan_evasion": '''\
// Frida: Hide target regions from /proc/self/maps readers
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc/self/maps") !== -1) {
            // Return an fd to a filtered copy that hides injected libraries
            // (extend with Memory.alloc + NativeFunction for full filtering)
            send("[*] /proc/self/maps access intercepted");
        }
    }
});
Interceptor.attach(Module.findExportByName(null, "inotify_add_watch"), {
    onEnter: function(args) {
        var path = args[1].readUtf8String();
        if (path && path.indexOf("/proc") !== -1) {
            send("[*] Blocked inotify watch on " + path);
            args[1] = Memory.allocUtf8String("/dev/null");
        }
    }
});
''',
        "speed_hack_bypass": '''\
// Frida: Hook SystemClock to allow speed manipulation
Java.perform(function() {
    var SystemClock = Java.use("android.os.SystemClock");
    var System = Java.use("java.lang.System");
    var speedMultiplier = 1.0;
    var baseElapsed = SystemClock.elapsedRealtime();
    var baseNano = System.nanoTime();

    SystemClock.elapsedRealtime.implementation = function() {
        var real = this.elapsedRealtime();
        var delta = real - baseElapsed;
        return baseElapsed + Math.floor(delta * speedMultiplier);
    };

    System.nanoTime.implementation = function() {
        var real = this.nanoTime();
        var delta = real - baseNano;
        return baseNano + Math.floor(delta * speedMultiplier);
    };

    send("[*] Speed hack hooks installed  (multiplier=" + speedMultiplier + ")");
});
''',
        "value_freeze": '''\
// Frida: ArtHook-style value freezer
// Usage: call freezeAddress(ptr("0xADDRESS"), 4, 999999);
function freezeAddress(addr, size, value) {
    var buf = Memory.alloc(size);
    if (size === 4) buf.writeS32(value);
    else if (size === 8) buf.writeS64(value);

    setInterval(function() {
        Memory.copy(addr, buf, size);
    }, 50);
    send("[*] Freezing " + addr + " => " + value);
}

// Auto-scan example: freeze first match of a known value
// var results = Memory.scanSync(Process.enumerateRanges('rw-')[0].base, 0x1000, "39 05 00 00");
// if (results.length > 0) freezeAddress(results[0].address, 4, 99999);
''',
        "ptrace_bypass": '''\
// Frida: Bypass ptrace-based anti-debug
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
        if (this.request === 0) {  // PTRACE_TRACEME
            send("[*] Bypassing PTRACE_TRACEME");
        }
    },
    onLeave: function(retval) {
        if (this.request === 0) {
            retval.replace(ptr(0));
        }
    }
});

// Patch TracerPid reads
Interceptor.attach(Module.findExportByName(null, "fgets"), {
    onEnter: function(args) {
        this.buf = args[0];
    },
    onLeave: function(retval) {
        if (this.buf) {
            try {
                var line = this.buf.readUtf8String();
                if (line && line.indexOf("TracerPid") !== -1) {
                    this.buf.writeUtf8String("TracerPid:\\t0\\n");
                    send("[*] TracerPid spoofed to 0");
                }
            } catch(e) {}
        }
    }
});
''',
        "cheat_tool_hiding": '''\
// Frida: Hide cheat-tool packages from PackageManager queries
Java.perform(function() {
    var HIDDEN = ["com.gameguardian", "org.cheatengine", "com.dimonvideo.luckypatcher",
                  "cc.madkite.freedom", "com.igg.assistant"];
    var PM = Java.use("android.app.ApplicationPackageManager");

    PM.getInstalledPackages.overload("int").implementation = function(flags) {
        var list = this.getInstalledPackages(flags);
        var iterator = list.iterator();
        while (iterator.hasNext()) {
            var pkg = iterator.next();
            var name = pkg.packageName.value;
            for (var i = 0; i < HIDDEN.length; i++) {
                if (name.indexOf(HIDDEN[i]) !== -1) {
                    iterator.remove();
                    send("[*] Hidden package: " + name);
                    break;
                }
            }
        }
        return list;
    };
});
''',
    }

    # ──────────────────────────────────────────────────────────────────
    #  Public entry point
    # ──────────────────────────────────────────────────────────────────
    @staticmethod
    def analyze(apk_path, structure_data=None, decompiled_dir=None):
        result = {
            "available": False,
            "anticheat_systems": [],
            "memory_protections": [],
            "reverse_commands": [],
            "exploit_surfaces": [],
            "asset_protection": [],
            "frida_bypass_scripts": {},
            "risk_level": "unknown",
            "summary": "",
        }
        try:
            corpus = GameAntiCheatAnalyzer._build_corpus(apk_path, structure_data, decompiled_dir)
            if not corpus["strings"] and not corpus["files"]:
                result["summary"] = "Could not extract any searchable content from the APK."
                return result

            result["available"] = True

            result["anticheat_systems"] = GameAntiCheatAnalyzer._detect_anticheat(corpus)
            result["memory_protections"] = GameAntiCheatAnalyzer._detect_memory_protections(corpus)
            result["reverse_commands"] = GameAntiCheatAnalyzer._detect_engine_commands(corpus)
            result["exploit_surfaces"] = GameAntiCheatAnalyzer._detect_exploit_surfaces(corpus)
            result["asset_protection"] = GameAntiCheatAnalyzer._detect_asset_protection(corpus)
            result["frida_bypass_scripts"] = GameAntiCheatAnalyzer._select_frida_scripts(
                result["anticheat_systems"], result["memory_protections"])
            result["risk_level"] = GameAntiCheatAnalyzer._compute_risk(
                result["anticheat_systems"], result["memory_protections"])
            result["summary"] = GameAntiCheatAnalyzer._build_summary(result)
        except Exception as e:
            result["summary"] = f"GameAntiCheatAnalyzer error: {e}"
        return result

    # ──────────────────────────────────────────────────────────────────
    #  Corpus builder – collects searchable strings & file paths
    # ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _build_corpus(apk_path, structure_data, decompiled_dir):
        corpus = {"strings": set(), "files": set(), "raw_chunks": []}

        # Zip scan
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    corpus["files"].add(info.filename)
                    # Read small-ish text-like entries for string scanning
                    if info.file_size < 5 * 1024 * 1024:
                        try:
                            raw = zf.read(info.filename)
                            text = raw.decode("utf-8", errors="ignore")
                            corpus["strings"].update(
                                re.findall(r'[\x20-\x7E]{4,}', text))
                            corpus["raw_chunks"].append(text)
                        except Exception:
                            pass
        except Exception:
            pass

        # Structure data file list
        if structure_data:
            try:
                for f in structure_data.get("files", []):
                    name = f if isinstance(f, str) else f.get("path", "")
                    if name:
                        corpus["files"].add(name)
            except Exception:
                pass

        # Walk decompiled directory
        if decompiled_dir and os.path.isdir(decompiled_dir):
            try:
                for root, _dirs, files in os.walk(decompiled_dir):
                    for fn in files:
                        fpath = os.path.join(root, fn)
                        corpus["files"].add(fpath)
                        if fn.endswith((".smali", ".java", ".xml", ".json", ".txt", ".cfg", ".properties")):
                            try:
                                with open(fpath, "r", errors="ignore") as fh:
                                    text = fh.read(2 * 1024 * 1024)
                                    corpus["strings"].update(
                                        re.findall(r'[\x20-\x7E]{4,}', text))
                                    corpus["raw_chunks"].append(text)
                            except Exception:
                                pass
            except Exception:
                pass

        return corpus

    # ──────────────────────────────────────────────────────────────────
    #  Detection helpers
    # ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _match_strings(corpus, needles):
        """Return list of evidence strings found in the corpus."""
        found = []
        all_text = " ".join(corpus.get("raw_chunks", []))
        all_files = " ".join(corpus.get("files", set()))
        for needle in needles:
            if needle in all_text or needle in all_files:
                found.append(needle)
            else:
                for s in corpus.get("strings", set()):
                    if needle.lower() in s.lower():
                        found.append(needle)
                        break
        return found

    @staticmethod
    def _match_libs(corpus, libs):
        found = []
        for lib in libs:
            for f in corpus.get("files", set()):
                if lib in f:
                    found.append(lib)
                    break
        return found

    # ── 1. Anti-cheat detection ───────────────────────────────────────
    @staticmethod
    def _detect_anticheat(corpus):
        detections = []
        for name, sig in GameAntiCheatAnalyzer.ANTICHEAT_SIGNATURES.items():
            try:
                ev_strings = GameAntiCheatAnalyzer._match_strings(corpus, sig["strings"])
                ev_libs = GameAntiCheatAnalyzer._match_libs(corpus, sig["libs"])
                if ev_strings or ev_libs:
                    version_hint = "unknown"
                    for s in corpus.get("strings", set()):
                        m = re.search(
                            rf'(?i)(?:{re.escape(name.split()[0])})\s*v?([\d]+\.[\d]+[\.\d]*)', s)
                        if m:
                            version_hint = m.group(1)
                            break
                    detections.append({
                        "name": name,
                        "version_hint": version_hint,
                        "evidence_strings": ev_strings,
                        "evidence_libs": ev_libs,
                        "bypass_difficulty": sig["bypass_difficulty"],
                    })
            except Exception:
                pass
        return detections

    # ── 2. Memory protections ─────────────────────────────────────────
    @staticmethod
    def _detect_memory_protections(corpus):
        protections = []
        for key, pat in GameAntiCheatAnalyzer.MEMORY_PROTECTION_PATTERNS.items():
            try:
                ev = GameAntiCheatAnalyzer._match_strings(corpus, pat["strings"])
                if ev:
                    protections.append({
                        "id": key,
                        "type": pat["type"],
                        "evidence": ev,
                        "implementation": f"Detected via: {', '.join(ev)}",
                        "bypass_method": pat["bypass"],
                    })
            except Exception:
                pass
        return protections

    # ── 3. Reverse-engineering commands ───────────────────────────────
    @staticmethod
    def _detect_engine_commands(corpus):
        results = []
        for engine, info in GameAntiCheatAnalyzer.ENGINE_RE_COMMANDS.items():
            try:
                ev = GameAntiCheatAnalyzer._match_strings(corpus, info["markers"])
                ev_libs = GameAntiCheatAnalyzer._match_libs(corpus, info["markers"])
                if ev or ev_libs:
                    results.append({
                        "engine": engine,
                        "evidence": ev + ev_libs,
                        "commands": info["commands"],
                    })
            except Exception:
                pass
        return results

    # ── 4. Exploit surfaces (wallhack / ESP / aimbot) ─────────────────
    @staticmethod
    def _detect_exploit_surfaces(corpus):
        surfaces = []
        for key, pat in GameAntiCheatAnalyzer.EXPLOIT_SURFACE_PATTERNS.items():
            try:
                ev = GameAntiCheatAnalyzer._match_strings(corpus, pat["strings"])
                if ev:
                    surfaces.append({
                        "id": key,
                        "type": pat["type"],
                        "detected_countermeasures": ev,
                        "exploitable_surface": f"Strings found suggest {pat['type']} surface is present",
                    })
            except Exception:
                pass
        return surfaces

    # ── 5. Asset protection ───────────────────────────────────────────
    @staticmethod
    def _detect_asset_protection(corpus):
        protections = []
        for key, pat in GameAntiCheatAnalyzer.ASSET_PROTECTION_PATTERNS.items():
            try:
                ev = GameAntiCheatAnalyzer._match_strings(corpus, pat["strings"])
                if ev:
                    protections.append({
                        "id": key,
                        "type": pat["type"],
                        "encryption_evidence": ev,
                        "extraction_feasibility": pat["extraction"],
                    })
            except Exception:
                pass
        return protections

    # ── 6. Select Frida scripts based on findings ─────────────────────
    @staticmethod
    def _select_frida_scripts(anticheat_systems, memory_protections):
        scripts = {}
        prot_ids = {p["id"] for p in memory_protections}

        # Always include ptrace bypass if anti-debug detected
        if "ptrace_antidebug" in prot_ids:
            scripts["ptrace_bypass"] = GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["ptrace_bypass"]

        if "proc_maps_monitoring" in prot_ids:
            scripts["memory_scan_evasion"] = GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["memory_scan_evasion"]

        if "speed_hack_detection" in prot_ids:
            scripts["speed_hack_bypass"] = GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["speed_hack_bypass"]

        if "value_encryption" in prot_ids:
            scripts["value_freeze"] = GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["value_freeze"]

        if "cheat_tool_detection" in prot_ids:
            scripts["cheat_tool_hiding"] = GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["cheat_tool_hiding"]

        # If any anti-cheat system is detected, include core bypass scripts
        if anticheat_systems:
            scripts.setdefault("ptrace_bypass",
                               GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["ptrace_bypass"])
            scripts.setdefault("memory_scan_evasion",
                               GameAntiCheatAnalyzer.FRIDA_BYPASS_SCRIPTS["memory_scan_evasion"])

        return scripts

    # ── 7. Risk level ─────────────────────────────────────────────────
    @staticmethod
    def _compute_risk(anticheat_systems, memory_protections):
        if not anticheat_systems and not memory_protections:
            return "low"
        difficulty_map = {
            "medium": 1, "hard": 2, "very_hard": 3, "extremely_hard": 4,
        }
        max_diff = 0
        for ac in anticheat_systems:
            max_diff = max(max_diff, difficulty_map.get(ac.get("bypass_difficulty", ""), 0))
        if max_diff >= 3 or len(anticheat_systems) >= 2:
            return "critical"
        if max_diff >= 2 or len(memory_protections) >= 3:
            return "high"
        if anticheat_systems or memory_protections:
            return "medium"
        return "low"

    # ── 8. Summary ────────────────────────────────────────────────────
    @staticmethod
    def _build_summary(result):
        parts = []
        n_ac = len(result["anticheat_systems"])
        n_mp = len(result["memory_protections"])
        n_eng = len(result["reverse_commands"])
        n_es = len(result["exploit_surfaces"])
        n_ap = len(result["asset_protection"])
        n_fs = len(result["frida_bypass_scripts"])

        if n_ac:
            names = ", ".join(a["name"] for a in result["anticheat_systems"])
            parts.append(f"{n_ac} anti-cheat system(s) detected: {names}")
        if n_mp:
            parts.append(f"{n_mp} memory-protection mechanism(s) found")
        if n_eng:
            engines = ", ".join(e["engine"] for e in result["reverse_commands"])
            parts.append(f"Game engine(s): {engines}")
        if n_es:
            parts.append(f"{n_es} exploit surface(s) identified")
        if n_ap:
            parts.append(f"{n_ap} asset-protection layer(s) detected")
        if n_fs:
            parts.append(f"{n_fs} Frida bypass script(s) generated")
        parts.append(f"Overall risk level: {result['risk_level']}")

        return "; ".join(parts) if parts else "No game anti-cheat indicators found."


class BankingSecurityAnalyzer:
    # Limites para evitar consumo excesivo de memoria
    MAX_BLOB_SIZE = 30_000_000   # 30 MB maximo para el blob completo
    MAX_FILE_SIZE = 512_000      # 512 KB maximo por archivo individual

    @staticmethod
    def _scan_zip_content(apk_path):
        parts = []
        blob_size = 0
        file_list = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()
                for name in file_list:
                    if blob_size >= BankingSecurityAnalyzer.MAX_BLOB_SIZE:
                        break
                    if any(name.endswith(ext) for ext in
                           ('.xml', '.json', '.smali', '.properties',
                            '.txt', '.cfg', '.yml', '.yaml', '.js')):
                        try:
                            info = zf.getinfo(name)
                            if info.file_size > BankingSecurityAnalyzer.MAX_FILE_SIZE:
                                continue
                            raw = zf.read(name)
                            chunk = raw.decode('utf-8', errors='ignore')
                            parts.append(chunk)
                            blob_size += len(chunk)
                        except Exception:
                            pass
        except Exception:
            pass
        return "\n".join(parts), file_list

    @staticmethod
    def _scan_decompiled(decompiled_dir):
        parts = []
        blob_size = 0
        scan_exts = {'.smali', '.java', '.xml', '.json', '.properties',
                     '.yml', '.yaml', '.txt', '.cfg', '.js', '.kt'}
        try:
            for root, _, files in os.walk(decompiled_dir):
                if blob_size >= BankingSecurityAnalyzer.MAX_BLOB_SIZE:
                    break
                for f in files:
                    if blob_size >= BankingSecurityAnalyzer.MAX_BLOB_SIZE:
                        break
                    if os.path.splitext(f)[1].lower() in scan_exts:
                        try:
                            fp = os.path.join(root, f)
                            fsize = os.path.getsize(fp)
                            if fsize > BankingSecurityAnalyzer.MAX_FILE_SIZE:
                                continue
                            with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                                chunk = fh.read(BankingSecurityAnalyzer.MAX_FILE_SIZE)
                            parts.append(chunk)
                            blob_size += len(chunk)
                        except Exception:
                            pass
        except Exception:
            pass
        return "\n".join(parts)

    @staticmethod
    def _detect_secure_element(content, file_list):
        findings = []
        se_patterns = {
            'OMAPI': (r'android\.se\.omapi', 'SE access via OMAPI framework'),
            'SecureElementService': (r'SecureElementService', 'SE service binding'),
            'UICC': (r'\bUICC\b', 'UICC-based secure element'),
            'eSE': (r'\beSE\b', 'Embedded secure element'),
            'HCE': (r'\bHCE\b|Host\s*Card\s*Emulation', 'Host Card Emulation'),
            'NFC_CardEmulation': (r'android\.nfc\.cardemulation', 'NFC card emulation API'),
            'HostApduService': (r'HostApduService', 'On-device APDU service (HCE)'),
            'OffHostApduService': (r'OffHostApduService', 'Off-host APDU service (UICC/eSE)'),
        }
        for name, (pat, desc) in se_patterns.items():
            try:
                matches = re.findall(pat, content, re.IGNORECASE)
                if matches:
                    risk = 'High' if name in ('HCE', 'HostApduService') else 'Medium'
                    findings.append({
                        'se_type': name,
                        'description': desc,
                        'evidence_count': len(matches),
                        'risk_assessment': risk,
                    })
            except Exception:
                pass
        return findings

    @staticmethod
    def _detect_biometrics(content):
        findings = []
        frida_scripts = {}
        bio_patterns = {
            'BiometricPrompt': {
                'pattern': r'BiometricPrompt',
                'desc': 'Android BiometricPrompt API',
                'bypass_difficulty': 'Medium',
            },
            'FingerprintManager': {
                'pattern': r'FingerprintManager',
                'desc': 'Deprecated FingerprintManager API',
                'bypass_difficulty': 'Easy',
            },
            'BiometricManager': {
                'pattern': r'BiometricManager',
                'desc': 'BiometricManager capability check',
                'bypass_difficulty': 'Medium',
            },
            'CryptoObject': {
                'pattern': r'CryptoObject',
                'desc': 'Crypto-bound biometric authentication',
                'bypass_difficulty': 'Hard',
            },
            'Samsung_Pass': {
                'pattern': r'com\.samsung\.android\.sdk\.pass',
                'desc': 'Samsung Pass SDK integration',
                'bypass_difficulty': 'Medium',
            },
        }
        auth_patterns = {
            'setNegativeButtonText': r'setNegativeButtonText',
            'authenticate_call': r'\.authenticate\s*\(',
            'BIOMETRIC_STRONG': r'BIOMETRIC_STRONG',
            'BIOMETRIC_WEAK': r'BIOMETRIC_WEAK',
            'DEVICE_CREDENTIAL': r'DEVICE_CREDENTIAL',
        }
        has_crypto_binding = bool(re.search(r'CryptoObject', content))
        for name, info in bio_patterns.items():
            try:
                if re.search(info['pattern'], content):
                    auth_evidence = []
                    for aname, apat in auth_patterns.items():
                        if re.search(apat, content):
                            auth_evidence.append(aname)
                    findings.append({
                        'biometric_type': name,
                        'description': info['desc'],
                        'crypto_bound': 'yes' if has_crypto_binding else 'no',
                        'bypass_difficulty': info['bypass_difficulty'],
                        'auth_evidence': auth_evidence,
                    })
            except Exception:
                pass

        if re.search(r'BiometricPrompt', content):
            frida_scripts['biometric_prompt_bypass'] = (
                "Java.perform(function() {\n"
                "    var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');\n"
                "    var CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');\n"
                "    var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');\n"
                "    BiometricPrompt.authenticate.overload('android.os.CancellationSignal', "
                "'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(cancel, exec, cb) {\n"
                "        console.log('[BankingAnalyzer] BiometricPrompt.authenticate() intercepted');\n"
                "        var result = AuthResult.$new.call(AuthResult, null);\n"
                "        cb.onAuthenticationSucceeded(result);\n"
                "    };\n"
                "});\n"
            )
        if re.search(r'FingerprintManager', content):
            frida_scripts['fingerprint_manager_bypass'] = (
                "Java.perform(function() {\n"
                "    var FPManager = Java.use('android.hardware.fingerprint.FingerprintManager');\n"
                "    FPManager.authenticate.implementation = function(crypto, cancel, flags, cb, handler) {\n"
                "        console.log('[BankingAnalyzer] FingerprintManager.authenticate() intercepted');\n"
                "        var AuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');\n"
                "        var result = AuthResult.$new.call(AuthResult, null, null);\n"
                "        cb.onAuthenticationSucceeded.call(cb, result);\n"
                "    };\n"
                "});\n"
            )
        if re.search(r'com\.samsung\.android\.sdk\.pass', content):
            frida_scripts['samsung_pass_bypass'] = (
                "Java.perform(function() {\n"
                "    var SamsungPass = Java.use('com.samsung.android.sdk.pass.SpassFingerprint');\n"
                "    SamsungPass.startIdentify.implementation = function(listener) {\n"
                "        console.log('[BankingAnalyzer] Samsung Pass startIdentify() intercepted');\n"
                "        listener.onFinished.call(listener, 0);\n"
                "    };\n"
                "});\n"
            )
        if re.search(r'BIOMETRIC_STRONG|BIOMETRIC_WEAK|DEVICE_CREDENTIAL', content):
            frida_scripts['face_recognition_bypass'] = (
                "Java.perform(function() {\n"
                "    var BiometricManager = Java.use('android.hardware.biometrics.BiometricManager');\n"
                "    BiometricManager.canAuthenticate.overload('int').implementation = function(auth) {\n"
                "        console.log('[BankingAnalyzer] canAuthenticate(' + auth + ') -> SUCCESS');\n"
                "        return 0;\n"
                "    };\n"
                "});\n"
            )
        return findings, frida_scripts

    @staticmethod
    def _detect_hardware_keystore(content):
        findings = []
        frida_scripts = {}
        ks_patterns = {
            'StrongBoxBacked': {
                'pattern': r'setIsStrongBoxBacked',
                'desc': 'StrongBox hardware-backed keystore',
                'protection_level': 'Hardware (StrongBox)',
            },
            'UserAuthRequired': {
                'pattern': r'setUserAuthenticationRequired',
                'desc': 'Key requires user authentication',
                'protection_level': 'Auth-bound',
            },
            'AuthValidityDuration': {
                'pattern': r'setUserAuthenticationValidityDurationSeconds',
                'desc': 'Authentication validity window configured',
                'protection_level': 'Time-bound auth',
            },
            'UnlockedDeviceRequired': {
                'pattern': r'setUnlockedDeviceRequired',
                'desc': 'Key usable only when device unlocked',
                'protection_level': 'Device-state-bound',
            },
            'InvalidatedByBiometric': {
                'pattern': r'setInvalidatedByBiometricEnrollment',
                'desc': 'Key invalidated on new biometric enrollment',
                'protection_level': 'Biometric-enrollment-bound',
            },
            'KeyGenParameterSpec': {
                'pattern': r'KeyGenParameterSpec',
                'desc': 'Android KeyGen parameter specification',
                'protection_level': 'Software/Hardware',
            },
            'AttestationChallenge': {
                'pattern': r'setAttestationChallenge',
                'desc': 'Key attestation challenge configured',
                'protection_level': 'Attestation-verified',
            },
        }
        has_attestation = bool(re.search(r'setAttestationChallenge', content))
        for name, info in ks_patterns.items():
            try:
                matches = re.findall(info['pattern'], content)
                if matches:
                    findings.append({
                        'keystore_feature': name,
                        'description': info['desc'],
                        'key_protection_level': info['protection_level'],
                        'authentication_binding': name in (
                            'UserAuthRequired', 'AuthValidityDuration',
                            'InvalidatedByBiometric', 'UnlockedDeviceRequired'),
                        'attestation_usage': has_attestation,
                        'evidence_count': len(matches),
                    })
            except Exception:
                pass

        frida_scripts['keystore_operations_hook'] = (
            "Java.perform(function() {\n"
            "    var KeyStore = Java.use('java.security.KeyStore');\n"
            "    KeyStore.getEntry.overload('java.lang.String', "
            "'java.security.KeyStore$ProtectionParameter').implementation = function(alias, param) {\n"
            "        console.log('[BankingAnalyzer] KeyStore.getEntry: alias=' + alias);\n"
            "        var entry = this.getEntry(alias, param);\n"
            "        console.log('[BankingAnalyzer] Entry class: ' + entry.getClass().getName());\n"
            "        return entry;\n"
            "    };\n"
            "    var Cipher = Java.use('javax.crypto.Cipher');\n"
            "    Cipher.doFinal.overload('[B').implementation = function(input) {\n"
            "        console.log('[BankingAnalyzer] Cipher.doFinal called, input length=' + input.length);\n"
            "        var result = this.doFinal(input);\n"
            "        console.log('[BankingAnalyzer] Cipher.doFinal output length=' + result.length);\n"
            "        return result;\n"
            "    };\n"
            "    var KeyGenSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');\n"
            "    KeyGenSpec.build.implementation = function() {\n"
            "        console.log('[BankingAnalyzer] KeyGenParameterSpec.Builder.build() intercepted');\n"
            "        return this.build();\n"
            "    };\n"
            "});\n"
        )
        return findings, frida_scripts

    @staticmethod
    def _detect_tokens(content):
        findings = []
        frida_scripts = {}

        token_categories = {
            'JWT': {
                'patterns': [
                    (r'io\.jsonwebtoken', 'io.jsonwebtoken library'),
                    (r'com\.auth0\.jwt', 'Auth0 JWT library'),
                    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                     'JWT token pattern in strings'),
                ],
                'storage': 'SharedPreferences/Memory',
                'encryption': 'Base64-encoded (not encrypted)',
            },
            'OAuth2': {
                'patterns': [
                    (r'grant_type', 'OAuth2 grant_type parameter'),
                    (r'client_id', 'OAuth2 client_id'),
                    (r'client_secret', 'OAuth2 client_secret (SENSITIVE)'),
                    (r'access_token', 'OAuth2 access_token reference'),
                    (r'refresh_token', 'OAuth2 refresh_token reference'),
                ],
                'storage': 'SharedPreferences/AccountManager',
                'encryption': 'Varies',
            },
            'Session': {
                'patterns': [
                    (r'JSESSIONID', 'Java session ID'),
                    (r'PHPSESSID', 'PHP session ID'),
                    (r'Set-Cookie', 'Cookie-based session management'),
                ],
                'storage': 'CookieManager/WebView',
                'encryption': 'Transport-only (TLS)',
            },
            'Firebase': {
                'patterns': [
                    (r'FirebaseAuth', 'Firebase Authentication SDK'),
                    (r'getIdToken', 'Firebase ID token retrieval'),
                    (r'google-services\.json', 'Firebase configuration file'),
                    (r'AIza[0-9A-Za-z_-]{35}', 'Firebase API key pattern'),
                ],
                'storage': 'Firebase SDK internal',
                'encryption': 'SDK-managed',
            },
            'AWS': {
                'patterns': [
                    (r'AWSCognitoIdentityProvider', 'AWS Cognito identity provider'),
                    (r'CognitoUserPool', 'AWS Cognito user pool'),
                    (r'awsconfiguration\.json', 'AWS mobile configuration file'),
                    (r'AWSMobileClient', 'AWS Mobile Client SDK'),
                ],
                'storage': 'SharedPreferences/AWS SDK',
                'encryption': 'SDK-managed',
            },
        }

        for cat_name, cat_info in token_categories.items():
            evidence = []
            for pat, desc in cat_info['patterns']:
                try:
                    if re.search(pat, content):
                        evidence.append(desc)
                except Exception:
                    pass
            if evidence:
                findings.append({
                    'token_type': cat_name,
                    'evidence': evidence,
                    'storage_mechanism': cat_info['storage'],
                    'encryption_status': cat_info['encryption'],
                })

        frida_scripts['jwt_interceptor'] = (
            "Java.perform(function() {\n"
            "    try {\n"
            "        var JWT = Java.use('io.jsonwebtoken.Jwts');\n"
            "        JWT.parser.implementation = function() {\n"
            "            console.log('[BankingAnalyzer] JWT parser invoked');\n"
            "            return this.parser();\n"
            "        };\n"
            "    } catch(e) {}\n"
            "    var URL = Java.use('java.net.URL');\n"
            "    var HttpURLConnection = Java.use('java.net.HttpURLConnection');\n"
            "    HttpURLConnection.setRequestProperty.implementation = function(key, val) {\n"
            "        if (key && (key.toLowerCase() === 'authorization' || key.toLowerCase() === 'cookie')) {\n"
            "            console.log('[BankingAnalyzer] Header: ' + key + ' = ' + val);\n"
            "        }\n"
            "        return this.setRequestProperty(key, val);\n"
            "    };\n"
            "});\n"
        )
        frida_scripts['oauth_token_interceptor'] = (
            "Java.perform(function() {\n"
            "    var SharedPrefs = Java.use('android.app.SharedPreferencesImpl');\n"
            "    SharedPrefs.getString.implementation = function(key, defVal) {\n"
            "        var val = this.getString(key, defVal);\n"
            "        var lk = key ? key.toLowerCase() : '';\n"
            "        if (lk.indexOf('token') !== -1 || lk.indexOf('auth') !== -1 || "
            "lk.indexOf('session') !== -1 || lk.indexOf('cookie') !== -1) {\n"
            "            console.log('[BankingAnalyzer] SharedPrefs.getString: ' + key + ' = ' + val);\n"
            "        }\n"
            "        return val;\n"
            "    };\n"
            "});\n"
        )
        frida_scripts['firebase_token_interceptor'] = (
            "Java.perform(function() {\n"
            "    try {\n"
            "        var FirebaseUser = Java.use('com.google.firebase.auth.FirebaseUser');\n"
            "        FirebaseUser.getIdToken.implementation = function(forceRefresh) {\n"
            "            console.log('[BankingAnalyzer] FirebaseUser.getIdToken(forceRefresh=' "
            "+ forceRefresh + ')');\n"
            "            return this.getIdToken(forceRefresh);\n"
            "        };\n"
            "    } catch(e) { console.log('[BankingAnalyzer] Firebase classes not found'); }\n"
            "});\n"
        )
        frida_scripts['aws_cognito_interceptor'] = (
            "Java.perform(function() {\n"
            "    try {\n"
            "        var AWSMobile = Java.use('com.amazonaws.mobile.client.AWSMobileClient');\n"
            "        AWSMobile.getTokens.implementation = function() {\n"
            "            var tokens = this.getTokens();\n"
            "            console.log('[BankingAnalyzer] AWS tokens retrieved');\n"
            "            return tokens;\n"
            "        };\n"
            "    } catch(e) { console.log('[BankingAnalyzer] AWS classes not found'); }\n"
            "});\n"
        )
        return findings, frida_scripts

    @staticmethod
    def _detect_anti_tampering(content):
        findings = []
        frida_scripts = {}

        protections = {
            'DexGuard_Enterprise': {
                'patterns': [r'com\.guardsquare\.dexguard', r'dexguard', r'classEncryption',
                             r'stringEncryption', r'assetEncryption', r'apiHiding'],
                'desc': 'DexGuard Enterprise by GuardSquare',
                'bypass_difficulty': 'Expert',
            },
            'AppGuard': {
                'patterns': [r'com\.appguard', r'appguard.*integrity', r'repackaging.*detect'],
                'desc': 'AppGuard integrity and repackaging protection',
                'bypass_difficulty': 'Hard',
            },
            'Arxan_DigitalAI': {
                'patterns': [r'com\.arxan', r'com\.digitalai', r'TransformIT',
                             r'arxan.*environment'],
                'desc': 'Arxan/Digital.ai application protection',
                'bypass_difficulty': 'Expert',
            },
            'Promon_SHIELD': {
                'patterns': [r'com\.promon\.shield', r'PromonShield', r'promon.*shielding'],
                'desc': 'Promon SHIELD app shielding',
                'bypass_difficulty': 'Expert',
            },
            'VMProtect': {
                'patterns': [r'vmprotect', r'vmp\.'],
                'desc': 'VMProtect code virtualization',
                'bypass_difficulty': 'Expert',
            },
            'Custom_AntiTamper': {
                'patterns': [r'PackageManager\.GET_SIGNATURES', r'GET_SIGNING_CERTIFICATES',
                             r'signatures\[0\]', r'getPackageInfo.*signatures',
                             r'getInstallerPackageName'],
                'desc': 'Custom signature/installer verification',
                'bypass_difficulty': 'Medium',
            },
        }

        for name, info in protections.items():
            evidence = []
            for pat in info['patterns']:
                try:
                    if re.search(pat, content, re.IGNORECASE):
                        evidence.append(pat)
                except Exception:
                    pass
            if evidence:
                findings.append({
                    'protection_name': name,
                    'description': info['desc'],
                    'detection_evidence': evidence,
                    'bypass_difficulty': info['bypass_difficulty'],
                })

        frida_scripts['dexguard_bypass'] = (
            "Java.perform(function() {\n"
            "    try {\n"
            "        var dg = Java.use('com.guardsquare.dexguard.runtime.detection.RootDetector');\n"
            "        dg.isDeviceRooted.implementation = function() {\n"
            "            console.log('[BankingAnalyzer] DexGuard root check bypassed');\n"
            "            return false;\n"
            "        };\n"
            "    } catch(e) { console.log('[BankingAnalyzer] DexGuard classes not found'); }\n"
            "});\n"
        )
        frida_scripts['signature_verification_bypass'] = (
            "Java.perform(function() {\n"
            "    var PM = Java.use('android.app.ApplicationPackageManager');\n"
            "    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = "
            "function(pkg, flags) {\n"
            "        console.log('[BankingAnalyzer] getPackageInfo(' + pkg + ', ' + flags + ')');\n"
            "        if (flags & 0x40) {\n"
            "            console.log('[BankingAnalyzer] GET_SIGNATURES flag detected, returning original');\n"
            "        }\n"
            "        return this.getPackageInfo(pkg, flags);\n"
            "    };\n"
            "    PM.getInstallerPackageName.implementation = function(pkg) {\n"
            "        console.log('[BankingAnalyzer] Installer check bypassed -> com.android.vending');\n"
            "        return 'com.android.vending';\n"
            "    };\n"
            "});\n"
        )
        frida_scripts['promon_shield_bypass'] = (
            "Java.perform(function() {\n"
            "    try {\n"
            "        var shield = Java.use('com.promon.shield.PromonShield');\n"
            "        shield.isRooted.implementation = function() { return false; };\n"
            "        shield.isHooked.implementation = function() { return false; };\n"
            "        shield.isEmulator.implementation = function() { return false; };\n"
            "        console.log('[BankingAnalyzer] Promon SHIELD checks bypassed');\n"
            "    } catch(e) { console.log('[BankingAnalyzer] Promon classes not found'); }\n"
            "});\n"
        )
        return findings, frida_scripts

    @staticmethod
    def _detect_banking_patterns(content):
        findings = []

        pci_patterns = [
            (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 'Card number pattern (PAN)'),
            (r'PAN|cardNumber|card_number|primaryAccountNumber', 'PAN reference'),
            (r'mask.*card|card.*mask|\*{4,}', 'PAN masking logic'),
            (r'[Cc][Vv][Vv]|cvv2|cvc|securityCode|security_code', 'CVV processing'),
        ]
        pci_evidence = []
        for pat, desc in pci_patterns:
            try:
                if re.search(pat, content):
                    pci_evidence.append(desc)
            except Exception:
                pass
        if pci_evidence:
            findings.append({
                'pattern_type': 'PCI_DSS_Indicators',
                'evidence': pci_evidence,
                'compliance_status': 'Requires review',
            })

        keyboard_patterns = [
            (r'CustomKeyboard|SecureKeyboard|PinKeyboard|custom.*keyboard', 'Custom keyboard'),
            (r'AccessibilityService|isAccessibilityEnabled|accessibilityBlocker',
             'Accessibility service handling'),
        ]
        kb_evidence = []
        for pat, desc in keyboard_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    kb_evidence.append(desc)
            except Exception:
                pass
        if kb_evidence:
            findings.append({
                'pattern_type': 'Secure_Keyboard',
                'evidence': kb_evidence,
                'compliance_status': 'Implemented' if len(kb_evidence) > 1 else 'Partial',
            })

        screen_patterns = [
            (r'FLAG_SECURE', 'FLAG_SECURE window flag'),
            (r'setSecure|getWindow\(\)\.setFlags.*FLAG_SECURE', 'setSecure invocation'),
        ]
        sc_evidence = []
        for pat, desc in screen_patterns:
            try:
                if re.search(pat, content):
                    sc_evidence.append(desc)
            except Exception:
                pass
        if sc_evidence:
            findings.append({
                'pattern_type': 'Screen_Capture_Prevention',
                'evidence': sc_evidence,
                'compliance_status': 'Implemented',
            })

        root_patterns = [
            r'su\b', r'/system/xbin/su', r'/system/bin/su', r'Superuser\.apk',
            r'com\.topjohnwu\.magisk', r'com\.noshufou\.android\.su',
            r'eu\.chainfire\.supersu', r'test-keys', r'which.*su',
            r'RootBeer', r'rootcloak', r'isRooted', r'checkRoot',
            r'SafetyNet', r'safetynet', r'PlayIntegrity', r'IntegrityManager',
        ]
        root_count = 0
        for pat in root_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    root_count += 1
            except Exception:
                pass
        if root_count > 0:
            if root_count >= 8:
                depth = 'Comprehensive'
            elif root_count >= 4:
                depth = 'Moderate'
            else:
                depth = 'Basic'
            findings.append({
                'pattern_type': 'Root_Detection',
                'evidence': [f'{root_count} detection methods found'],
                'compliance_status': depth,
            })

        binding_patterns = [
            (r'ANDROID_ID|Settings\.Secure.*android_id', 'ANDROID_ID usage'),
            (r'Build\.SERIAL|getSerial', 'Build.SERIAL usage'),
            (r'fingerprint|deviceFingerprint|device_fingerprint', 'Device fingerprinting'),
            (r'TelephonyManager.*getDeviceId|getImei', 'Hardware ID retrieval'),
        ]
        bind_evidence = []
        for pat, desc in binding_patterns:
            try:
                if re.search(pat, content, re.IGNORECASE):
                    bind_evidence.append(desc)
            except Exception:
                pass
        if bind_evidence:
            findings.append({
                'pattern_type': 'Device_Binding',
                'evidence': bind_evidence,
                'compliance_status': 'Implemented' if len(bind_evidence) >= 2 else 'Partial',
            })

        return findings

    @staticmethod
    def analyze(apk_path, manifest_data=None, decompiled_dir=None, structure_data=None):
        result = {
            'available': False,
            'secure_element': [],
            'biometric_analysis': [],
            'hardware_keystore': [],
            'token_extraction': [],
            'anti_tampering': [],
            'banking_patterns': [],
            'frida_bypass_scripts': {},
            'risk_level': 'Low',
            'summary': '',
        }
        try:
            content = ""
            file_list = []

            if apk_path and os.path.isfile(apk_path):
                zip_content, file_list = BankingSecurityAnalyzer._scan_zip_content(apk_path)
                content += zip_content

            if decompiled_dir and os.path.isdir(decompiled_dir):
                content += BankingSecurityAnalyzer._scan_decompiled(decompiled_dir)

            if not content:
                result['summary'] = 'No content available for banking security analysis'
                return result

            result['available'] = True
            all_frida = {}

            result['secure_element'] = BankingSecurityAnalyzer._detect_secure_element(
                content, file_list)

            bio_findings, bio_frida = BankingSecurityAnalyzer._detect_biometrics(content)
            result['biometric_analysis'] = bio_findings
            all_frida.update(bio_frida)

            ks_findings, ks_frida = BankingSecurityAnalyzer._detect_hardware_keystore(content)
            result['hardware_keystore'] = ks_findings
            all_frida.update(ks_frida)

            tok_findings, tok_frida = BankingSecurityAnalyzer._detect_tokens(content)
            result['token_extraction'] = tok_findings
            all_frida.update(tok_frida)

            at_findings, at_frida = BankingSecurityAnalyzer._detect_anti_tampering(content)
            result['anti_tampering'] = at_findings
            all_frida.update(at_frida)

            result['banking_patterns'] = BankingSecurityAnalyzer._detect_banking_patterns(content)

            result['frida_bypass_scripts'] = all_frida

            total_findings = (len(result['secure_element']) +
                              len(result['biometric_analysis']) +
                              len(result['hardware_keystore']) +
                              len(result['token_extraction']) +
                              len(result['anti_tampering']) +
                              len(result['banking_patterns']))

            expert_protections = sum(
                1 for f in result['anti_tampering']
                if f.get('bypass_difficulty') == 'Expert')
            has_crypto_bio = any(
                f.get('crypto_bound') == 'yes' for f in result['biometric_analysis'])
            has_attestation = any(
                f.get('attestation_usage') for f in result['hardware_keystore'])
            has_se = len(result['secure_element']) > 0
            has_tokens_exposed = any(
                f.get('encryption_status', '').startswith('Base64')
                for f in result['token_extraction'])

            risk_score = 0
            if has_tokens_exposed:
                risk_score += 3
            if not has_crypto_bio and result['biometric_analysis']:
                risk_score += 2
            if not result['anti_tampering']:
                risk_score += 2
            if not has_attestation and result['hardware_keystore']:
                risk_score += 1
            if expert_protections >= 2:
                risk_score -= 2
            if has_se:
                risk_score -= 1
            if has_crypto_bio:
                risk_score -= 1

            if risk_score >= 5:
                result['risk_level'] = 'Critical'
            elif risk_score >= 3:
                result['risk_level'] = 'High'
            elif risk_score >= 1:
                result['risk_level'] = 'Medium'
            else:
                result['risk_level'] = 'Low'

            parts = [f"Banking security analysis: {total_findings} findings"]
            if result['secure_element']:
                parts.append(f"{len(result['secure_element'])} SE feature(s)")
            if result['biometric_analysis']:
                parts.append(f"{len(result['biometric_analysis'])} biometric type(s)")
            if result['hardware_keystore']:
                parts.append(f"{len(result['hardware_keystore'])} keystore feature(s)")
            if result['token_extraction']:
                parts.append(f"{len(result['token_extraction'])} token type(s)")
            if result['anti_tampering']:
                names = [f['protection_name'] for f in result['anti_tampering']]
                parts.append(f"Anti-tamper: {', '.join(names)}")
            if result['banking_patterns']:
                ptypes = [f['pattern_type'] for f in result['banking_patterns']]
                parts.append(f"Banking: {', '.join(ptypes)}")
            parts.append(f"Risk: {result['risk_level']}")
            parts.append(f"{len(all_frida)} Frida script(s) generated")
            result['summary'] = '. '.join(parts)

        except Exception as e:
            result['summary'] = f'Banking security analysis error: {str(e)}'

        return result


# ====================================================================
# MODULO: FRAMEWORK ANALYZER - DETECCION DE FRAMEWORKS MOVILES
# ====================================================================

class FrameworkAnalyzer:
    """Detecta y analiza frameworks de desarrollo móvil en APKs:
    Flutter, React Native, Unity IL2CPP, Unreal Engine, Godot,
    Xamarin, Cordova/Ionic y Kotlin Multiplatform."""

    @staticmethod
    def analyze(apk_path, structure_data=None, decompiled_dir=None):
        result = {
            'available': False,
            'detected_frameworks': [],
            'primary_framework': None,
            'summary': ''
        }
        try:
            file_list = []
            if structure_data and isinstance(structure_data, dict):
                file_list = structure_data.get('all_files', [])
                if not file_list:
                    file_list = structure_data.get('files', [])
            if not file_list:
                try:
                    with zipfile.ZipFile(apk_path, 'r') as zf:
                        file_list = zf.namelist()
                except Exception:
                    pass

            decompiled_files = []
            if decompiled_dir and os.path.isdir(decompiled_dir):
                try:
                    for root, _dirs, fnames in os.walk(decompiled_dir):
                        for fn in fnames:
                            rel = os.path.relpath(os.path.join(root, fn), decompiled_dir)
                            decompiled_files.append(rel)
                except Exception:
                    pass

            all_files = file_list + decompiled_files
            all_lower = [f.lower() for f in all_files]

            detectors = [
                FrameworkAnalyzer._detect_flutter,
                FrameworkAnalyzer._detect_react_native,
                FrameworkAnalyzer._detect_unity,
                FrameworkAnalyzer._detect_unreal,
                FrameworkAnalyzer._detect_godot,
                FrameworkAnalyzer._detect_xamarin,
                FrameworkAnalyzer._detect_cordova,
                FrameworkAnalyzer._detect_kotlin_multiplatform,
            ]

            for detector in detectors:
                try:
                    fw = detector(apk_path, all_files, all_lower, decompiled_dir)
                    if fw:
                        result['detected_frameworks'].append(fw)
                except Exception:
                    pass

            if result['detected_frameworks']:
                result['available'] = True
                priority = {'High': 0, 'Medium': 1, 'Low': 2}
                result['detected_frameworks'].sort(
                    key=lambda x: priority.get(x.get('confidence', 'Low'), 2))
                result['primary_framework'] = result['detected_frameworks'][0]['name']
                names = [f['name'] for f in result['detected_frameworks']]
                result['summary'] = (
                    f"Detectados {len(names)} framework(s): {', '.join(names)}. "
                    f"Principal: {result['primary_framework']}"
                )
            else:
                result['summary'] = "No se detectaron frameworks de terceros conocidos."
        except Exception:
            result['summary'] = "Error durante el análisis de frameworks."
        return result

    # ---- Flutter ----
    @staticmethod
    def _detect_flutter(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'libflutter.so': False,
            'libapp.so': False,
            'flutter_assets': False,
            'kernel_blob.bin': False,
            'AssetManifest.json': False,
        }
        evidence = []
        for f in all_lower:
            if 'libflutter.so' in f:
                indicators['libflutter.so'] = True
                evidence.append(f"Encontrado libflutter.so: {f}")
            if 'libapp.so' in f:
                indicators['libapp.so'] = True
                evidence.append(f"Encontrado libapp.so: {f}")
            if 'flutter_assets' in f:
                indicators['flutter_assets'] = True
                evidence.append(f"Directorio flutter_assets: {f}")
            if 'kernel_blob.bin' in f:
                indicators['kernel_blob.bin'] = True
                evidence.append(f"Encontrado kernel_blob.bin: {f}")
            if 'assetmanifest.json' in f:
                indicators['AssetManifest.json'] = True
                evidence.append(f"Encontrado AssetManifest.json: {f}")

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        confidence = 'High' if found >= 3 else ('Medium' if found >= 2 else 'Low')

        flutter_version = None
        dart_version = None
        engine_type = 'Unknown'
        dart_snapshot = False

        # Dart AOT snapshot header check in libapp.so
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    nl = name.lower()
                    if 'libapp.so' in nl:
                        data = zf.read(name)[:256]
                        if b'_kDartVmSnapshotInstructions' in data or b'\x00dart' in data:
                            dart_snapshot = True
                            engine_type = 'AOT'
                            evidence.append("Dart AOT snapshot detectado en libapp.so")
                        break
                    if 'kernel_blob.bin' in nl:
                        engine_type = 'JIT'
                        evidence.append("Modo JIT detectado (kernel_blob.bin presente)")

                # Flutter version from libflutter.so strings
                for name in zf.namelist():
                    if 'libflutter.so' in name.lower():
                        try:
                            data = zf.read(name)
                            matches = re.findall(
                                rb'Flutter\s+(\d+\.\d+\.\d+)', data[:200000])
                            if matches:
                                flutter_version = matches[0].decode('utf-8', errors='ignore')
                                evidence.append(f"Flutter version: {flutter_version}")
                            dart_matches = re.findall(
                                rb'Dart\s+(\d+\.\d+\.\d+)', data[:200000])
                            if dart_matches:
                                dart_version = dart_matches[0].decode('utf-8', errors='ignore')
                                evidence.append(f"Dart version: {dart_version}")
                        except Exception:
                            pass
                        break
        except Exception:
            pass

        if indicators['kernel_blob.bin']:
            engine_type = 'JIT'

        commands = [
            {
                'tool': 'dart_decompiler',
                'command': f'dart_decompiler --input "{apk_path}" --output ./flutter_decompiled/',
                'description': 'Descompilar Dart AOT snapshot'
            },
            {
                'tool': 'flutter_reverser',
                'command': f'flutter_reverser -a "{apk_path}" -o ./flutter_reversed/',
                'description': 'Análisis reverso de app Flutter'
            },
            {
                'tool': 'reflutter',
                'command': f'reflutter "{apk_path}"',
                'description': 'Parchear Flutter para interceptar tráfico SSL'
            },
        ]

        frida_hooks = [
            {
                'name': 'Flutter HTTP Client Hook',
                'description': 'Interceptar peticiones HTTP de dart:io HttpClient',
                'script': (
                    "// Frida hook para dart:io HttpClient\n"
                    "Java.perform(function() {\n"
                    "    // Hook SSL verification bypass for Flutter\n"
                    "    var module = Process.findModuleByName('libflutter.so');\n"
                    "    if (module) {\n"
                    "        var ssl_verify = Module.findExportByName('libflutter.so', 'ssl_crypto_x509_session_verify_cert_chain');\n"
                    "        if (ssl_verify) {\n"
                    "            Interceptor.attach(ssl_verify, {\n"
                    "                onLeave: function(retval) { retval.replace(0x1); }\n"
                    "            });\n"
                    "            console.log('[+] Flutter SSL pinning bypassed');\n"
                    "        }\n"
                    "    }\n"
                    "});"
                )
            },
            {
                'name': 'Dart String Operations Hook',
                'description': 'Interceptar operaciones dart:core String',
                'script': (
                    "// Frida hook para dart:core String operations\n"
                    "var libapp = Process.findModuleByName('libapp.so');\n"
                    "if (libapp) {\n"
                    "    // Enumerate exports and hook string-related functions\n"
                    "    Module.enumerateExports('libapp.so', {\n"
                    "        onMatch: function(exp) {\n"
                    "            if (exp.name.indexOf('String') !== -1) {\n"
                    "                try {\n"
                    "                    Interceptor.attach(exp.address, {\n"
                    "                        onEnter: function(args) {\n"
                    "                            console.log('[Dart String] ' + exp.name);\n"
                    "                        }\n"
                    "                    });\n"
                    "                } catch(e) {}\n"
                    "            }\n"
                    "        },\n"
                    "        onComplete: function() {}\n"
                    "    });\n"
                    "}"
                )
            },
        ]

        return {
            'name': 'Flutter',
            'confidence': confidence,
            'version': flutter_version,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'dart_version': dart_version,
                'engine_type': engine_type,
                'dart_aot_snapshot': dart_snapshot,
                'indicators_matched': found,
            }
        }

    # ---- React Native ----
    @staticmethod
    def _detect_react_native(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'libreactnativejni.so': False,
            'index.android.bundle': False,
            'libjsc.so': False,
            'libhermes.so': False,
        }
        evidence = []
        bundle_path_in_zip = None

        for idx, f in enumerate(all_lower):
            if 'libreactnativejni.so' in f:
                indicators['libreactnativejni.so'] = True
                evidence.append(f"Encontrado libreactnativejni.so: {all_files[idx]}")
            if 'index.android.bundle' in f:
                indicators['index.android.bundle'] = True
                bundle_path_in_zip = all_files[idx] if idx < len(all_files) else f
                evidence.append(f"Encontrado index.android.bundle: {all_files[idx]}")
            if 'libjsc.so' in f:
                indicators['libjsc.so'] = True
                evidence.append(f"Encontrado libjsc.so (JavaScriptCore): {all_files[idx]}")
            if 'libhermes.so' in f:
                indicators['libhermes.so'] = True
                evidence.append(f"Encontrado libhermes.so (Hermes engine): {all_files[idx]}")

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        confidence = 'High' if found >= 2 else ('Medium' if found >= 1 and indicators['libreactnativejni.so'] else 'Low')

        engine = 'Unknown'
        if indicators['libhermes.so']:
            engine = 'Hermes'
        elif indicators['libjsc.so']:
            engine = 'JavaScriptCore (JSC)'

        hermes_bytecode = False
        bundle_size = 0
        has_source_maps = False

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Check Hermes bytecode header
                for name in zf.namelist():
                    if 'index.android.bundle' in name.lower():
                        bundle_path_in_zip = name
                        info = zf.getinfo(name)
                        bundle_size = info.file_size
                        data = zf.read(name)[:16]
                        # Hermes magic: 0x1F1903C103BC1FC6 (little-endian)
                        hermes_magic = b'\xc6\x1f\xbc\x03\xc1\x03\x19\x1f'
                        if data[:8] == hermes_magic:
                            hermes_bytecode = True
                            engine = 'Hermes (bytecode)'
                            evidence.append("Hermes bytecode header detectado (magic 0x1F1903C103BC1FC6)")
                        break

                # Source map references
                for name in zf.namelist():
                    nl = name.lower()
                    if nl.endswith('.map') or 'sourcemap' in nl or 'source-map' in nl:
                        has_source_maps = True
                        evidence.append(f"Source map encontrado: {name}")
                        break

                # Also check bundle content for sourceMappingURL
                if bundle_path_in_zip and not has_source_maps:
                    try:
                        tail = zf.read(bundle_path_in_zip)[-2048:]
                        if b'sourceMappingURL' in tail:
                            has_source_maps = True
                            evidence.append("Referencia sourceMappingURL en bundle")
                    except Exception:
                        pass
        except Exception:
            pass

        commands = []
        if hermes_bytecode:
            commands.extend([
                {
                    'tool': 'hermes-dec',
                    'command': f'hermes-dec --input "{apk_path}" --output ./rn_decompiled/',
                    'description': 'Descompilar Hermes bytecode a JavaScript'
                },
                {
                    'tool': 'hbc-decompiler',
                    'command': f'hbc-decompiler "{apk_path}" -o ./rn_hbc_output/',
                    'description': 'Decompilador alternativo de Hermes bytecode'
                },
            ])
        else:
            commands.append({
                'tool': 'js-beautify',
                'command': 'js-beautify assets/index.android.bundle > bundle_beautified.js',
                'description': 'Formatear bundle JavaScript para análisis'
            })

        frida_hooks = [
            {
                'name': 'React Native Bridge Hook',
                'description': 'Interceptar comunicaciones del bridge nativo',
                'script': (
                    "// Frida hook para React Native bridge\n"
                    "Java.perform(function() {\n"
                    "    var CatalystInstance = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');\n"
                    "    CatalystInstance.jniCallJSFunction.implementation = function(module, method, args) {\n"
                    "        console.log('[RN Bridge] ' + module + '.' + method + ' args=' + args);\n"
                    "        return this.jniCallJSFunction(module, method, args);\n"
                    "    };\n"
                    "});"
                )
            },
        ]

        return {
            'name': 'React Native',
            'confidence': confidence,
            'version': None,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'engine': engine,
                'hermes_bytecode': hermes_bytecode,
                'bundle_size': bundle_size,
                'has_source_maps': has_source_maps,
            }
        }

    # ---- Unity IL2CPP ----
    @staticmethod
    def _detect_unity(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'libunity.so': False,
            'libil2cpp.so': False,
            'bin_data': False,
            'globalgamemanagers': False,
            'UnityPlayer': False,
        }
        evidence = []

        for idx, f in enumerate(all_lower):
            if 'libunity.so' in f:
                indicators['libunity.so'] = True
                evidence.append(f"Encontrado libunity.so: {all_files[idx]}")
            if 'libil2cpp.so' in f:
                indicators['libil2cpp.so'] = True
                evidence.append(f"Encontrado libil2cpp.so (IL2CPP backend): {all_files[idx]}")
            if 'assets/bin/data/' in f:
                indicators['bin_data'] = True
            if 'globalgamemanagers' in f:
                indicators['globalgamemanagers'] = True
                evidence.append(f"Encontrado globalgamemanagers: {all_files[idx]}")
            if 'unityplayer' in f:
                indicators['UnityPlayer'] = True

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        confidence = 'High' if found >= 3 else ('Medium' if found >= 2 else 'Low')

        unity_version = None
        scripting_backend = 'Unknown'
        has_global_metadata = False

        if indicators['libil2cpp.so']:
            scripting_backend = 'IL2CPP'
        elif any('libmono' in f for f in all_lower):
            scripting_backend = 'Mono'

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Unity version from globalgamemanagers
                for name in zf.namelist():
                    if 'globalgamemanagers' in name.lower() and not name.lower().endswith('.assets'):
                        try:
                            data = zf.read(name)[:512]
                            matches = re.findall(rb'(\d+\.\d+\.\d+[a-z]\d*)', data)
                            if matches:
                                unity_version = matches[0].decode('utf-8', errors='ignore')
                                evidence.append(f"Unity version: {unity_version}")
                        except Exception:
                            pass
                        break

                # Global metadata
                for name in zf.namelist():
                    if 'global-metadata.dat' in name.lower():
                        has_global_metadata = True
                        evidence.append(f"Encontrado global-metadata.dat: {name}")
                        break
        except Exception:
            pass

        commands = [
            {
                'tool': 'Il2CppInspector',
                'command': (
                    'Il2CppInspector --bin lib/arm64-v8a/libil2cpp.so '
                    '--metadata assets/bin/Data/Managed/Metadata/global-metadata.dat '
                    '--output ./il2cpp_output/'
                ),
                'description': 'Extraer tipos, métodos y strings de IL2CPP'
            },
            {
                'tool': 'Il2CppDumper',
                'command': (
                    'Il2CppDumper lib/arm64-v8a/libil2cpp.so '
                    'assets/bin/Data/Managed/Metadata/global-metadata.dat ./il2cpp_dump/'
                ),
                'description': 'Dump de clases y métodos IL2CPP'
            },
            {
                'tool': 'il2cppdumper',
                'command': f'il2cppdumper -i "{apk_path}" -o ./il2cpp_cli_output/',
                'description': 'Análisis IL2CPP via CLI'
            },
        ]

        frida_hooks = [
            {
                'name': 'Unity IL2CPP Method Hook',
                'description': 'Hook métodos IL2CPP en runtime',
                'script': (
                    "// Frida hook para Unity IL2CPP\n"
                    "var il2cpp = Process.findModuleByName('libil2cpp.so');\n"
                    "if (il2cpp) {\n"
                    "    // Hook il2cpp_runtime_invoke\n"
                    "    var invoke = Module.findExportByName('libil2cpp.so', 'il2cpp_runtime_invoke');\n"
                    "    if (invoke) {\n"
                    "        Interceptor.attach(invoke, {\n"
                    "            onEnter: function(args) {\n"
                    "                var method = args[0];\n"
                    "                console.log('[IL2CPP] Method invoked at: ' + method);\n"
                    "            }\n"
                    "        });\n"
                    "    }\n"
                    "}"
                )
            },
        ]

        return {
            'name': 'Unity IL2CPP' if scripting_backend == 'IL2CPP' else 'Unity',
            'confidence': confidence,
            'version': unity_version,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'scripting_backend': scripting_backend,
                'has_global_metadata': has_global_metadata,
            }
        }

    # ---- Unreal Engine ----
    @staticmethod
    def _detect_unreal(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'libUE4.so': False,
            'pak_files': False,
            'commandline': False,
        }
        evidence = []
        pak_files = []

        for idx, f in enumerate(all_lower):
            if 'libue4.so' in f or 'libunreal.so' in f:
                indicators['libUE4.so'] = True
                evidence.append(f"Encontrado motor Unreal: {all_files[idx]}")
            if f.endswith('.pak'):
                indicators['pak_files'] = True
                pak_files.append(all_files[idx])
            if 'ue4commandline.txt' in f or 'uecommandline.txt' in f:
                indicators['commandline'] = True
                evidence.append(f"Encontrado UE command line: {all_files[idx]}")

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        if pak_files:
            evidence.append(f"PAK files encontrados: {len(pak_files)}")

        confidence = 'High' if found >= 2 else ('Medium' if indicators['libUE4.so'] else 'Low')

        ue_version = None
        total_asset_size = 0
        pak_encrypted = False

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for pf in pak_files:
                    try:
                        info = zf.getinfo(pf)
                        total_asset_size += info.file_size
                    except Exception:
                        pass

                # Check PAK encryption (read footer of first PAK)
                if pak_files:
                    try:
                        data = zf.read(pak_files[0])[-44:]
                        # PAK footer magic: 0x5A6F12E1
                        if len(data) >= 44:
                            magic = struct.unpack('<I', data[:4])[0]
                            if magic == 0x5A6F12E1:
                                version = struct.unpack('<I', data[4:8])[0]
                                ue_version = f"PAK v{version}"
                                evidence.append(f"PAK version: {version}")
                                encrypted_flag = data[40] if len(data) > 40 else 0
                                if encrypted_flag:
                                    pak_encrypted = True
                                    evidence.append("PAK files posiblemente encriptados")
                    except Exception:
                        pass

                # UE version from commandline
                for name in zf.namelist():
                    nl = name.lower()
                    if 'ue4commandline.txt' in nl or 'uecommandline.txt' in nl:
                        try:
                            content = zf.read(name).decode('utf-8', errors='ignore')
                            evidence.append(f"UE CommandLine: {content.strip()[:200]}")
                        except Exception:
                            pass
                        break
        except Exception:
            pass

        commands = [
            {
                'tool': 'UnrealPakTool',
                'command': f'UnrealPakTool "{pak_files[0] if pak_files else "*.pak"}" -Extract ./ue_extracted/',
                'description': 'Extraer contenido de PAK files'
            },
            {
                'tool': 'u4pak',
                'command': f'u4pak unpack "{pak_files[0] if pak_files else "*.pak"}" --output ./ue_unpacked/',
                'description': 'Desempaquetar PAK con u4pak'
            },
        ]

        frida_hooks = [
            {
                'name': 'Unreal Engine Hook',
                'description': 'Hook funciones principales de UE4',
                'script': (
                    "// Frida hook para Unreal Engine\n"
                    "var ue4 = Process.findModuleByName('libUE4.so');\n"
                    "if (ue4) {\n"
                    "    console.log('[UE4] Module base: ' + ue4.base);\n"
                    "    Module.enumerateExports('libUE4.so', {\n"
                    "        onMatch: function(exp) {\n"
                    "            if (exp.name.indexOf('FPakFile') !== -1) {\n"
                    "                console.log('[UE4 PAK] ' + exp.name + ' @ ' + exp.address);\n"
                    "            }\n"
                    "        },\n"
                    "        onComplete: function() {}\n"
                    "    });\n"
                    "}"
                )
            },
        ]

        return {
            'name': 'Unreal Engine',
            'confidence': confidence,
            'version': ue_version,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'pak_file_count': len(pak_files),
                'total_asset_size': total_asset_size,
                'pak_encrypted': pak_encrypted,
            }
        }

    # ---- Godot ----
    @staticmethod
    def _detect_godot(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'libgodot_android.so': False,
            'pck_files': False,
            'project_godot': False,
        }
        evidence = []
        pck_files = []

        for idx, f in enumerate(all_lower):
            if 'libgodot_android.so' in f:
                indicators['libgodot_android.so'] = True
                evidence.append(f"Encontrado libgodot_android.so: {all_files[idx]}")
            if f.endswith('.pck'):
                indicators['pck_files'] = True
                pck_files.append(all_files[idx])
            if 'project.godot' in f:
                indicators['project_godot'] = True
                evidence.append(f"Encontrada referencia project.godot: {all_files[idx]}")

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        if pck_files:
            evidence.append(f"PCK files encontrados: {len(pck_files)}")

        confidence = 'High' if found >= 2 else ('Medium' if indicators['libgodot_android.so'] else 'Low')

        godot_version = None
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if 'libgodot_android.so' in name.lower():
                        try:
                            data = zf.read(name)[:100000]
                            matches = re.findall(rb'Godot Engine v?(\d+\.\d+[\.\d]*)', data)
                            if matches:
                                godot_version = matches[0].decode('utf-8', errors='ignore')
                                evidence.append(f"Godot version: {godot_version}")
                        except Exception:
                            pass
                        break
        except Exception:
            pass

        commands = [
            {
                'tool': 'godotpcktool',
                'command': f'godotpcktool "{pck_files[0] if pck_files else "*.pck"}" --action extract --output ./godot_extracted/',
                'description': 'Extraer contenido de PCK files de Godot'
            },
        ]

        frida_hooks = []

        return {
            'name': 'Godot',
            'confidence': confidence,
            'version': godot_version,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'pck_files': pck_files,
            }
        }

    # ---- Xamarin ----
    @staticmethod
    def _detect_xamarin(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'libmonodroid.so': False,
            'libmonosgen': False,
            'assemblies_dll': False,
            'mono_android_dll': False,
        }
        evidence = []
        assemblies = []

        for idx, f in enumerate(all_lower):
            if 'libmonodroid.so' in f:
                indicators['libmonodroid.so'] = True
                evidence.append(f"Encontrado libmonodroid.so: {all_files[idx]}")
            if 'libmonosgen-2.0.so' in f or 'libmonosgen' in f:
                indicators['libmonosgen'] = True
                evidence.append(f"Encontrado libmonosgen: {all_files[idx]}")
            if 'assemblies/' in f and f.endswith('.dll'):
                indicators['assemblies_dll'] = True
                assemblies.append(all_files[idx])
            if 'mono.android.dll' in f:
                indicators['mono_android_dll'] = True
                evidence.append(f"Encontrado Mono.Android.dll: {all_files[idx]}")

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        if assemblies:
            evidence.append(f"Assemblies .NET encontrados: {len(assemblies)}")

        confidence = 'High' if found >= 3 else ('Medium' if found >= 2 else 'Low')

        mono_version = None
        has_aot = False
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    nl = name.lower()
                    if 'libmonosgen' in nl:
                        try:
                            data = zf.read(name)[:100000]
                            matches = re.findall(rb'Mono\s+(\d+\.\d+[\.\d]*)', data)
                            if matches:
                                mono_version = matches[0].decode('utf-8', errors='ignore')
                                evidence.append(f"Mono version: {mono_version}")
                        except Exception:
                            pass
                        break
                # AOT check
                for name in zf.namelist():
                    if name.lower().endswith('.dll.so') or 'aot-instances' in name.lower():
                        has_aot = True
                        evidence.append("AOT compilation detectada")
                        break
        except Exception:
            pass

        commands = [
            {
                'tool': 'ilspy',
                'command': 'ilspy assemblies/*.dll',
                'description': 'Descompilar assemblies .NET con ILSpy'
            },
            {
                'tool': 'dnSpy',
                'command': 'dnSpy assemblies/',
                'description': 'Abrir assemblies en dnSpy para análisis'
            },
            {
                'tool': 'dotPeek',
                'command': 'dotPeek assemblies/',
                'description': 'Descompilar con JetBrains dotPeek'
            },
        ]

        frida_hooks = [
            {
                'name': 'Xamarin Mono Hook',
                'description': 'Hook runtime Mono/Xamarin',
                'script': (
                    "// Frida hook para Xamarin/Mono\n"
                    "Java.perform(function() {\n"
                    "    var mono = Process.findModuleByName('libmonosgen-2.0.so');\n"
                    "    if (mono) {\n"
                    "        var mono_jit = Module.findExportByName('libmonosgen-2.0.so', 'mono_jit_runtime_invoke');\n"
                    "        if (mono_jit) {\n"
                    "            Interceptor.attach(mono_jit, {\n"
                    "                onEnter: function(args) {\n"
                    "                    console.log('[Xamarin] Method invoked');\n"
                    "                }\n"
                    "            });\n"
                    "        }\n"
                    "    }\n"
                    "});"
                )
            },
        ]

        return {
            'name': 'Xamarin',
            'confidence': confidence,
            'version': mono_version,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'mono_version': mono_version,
                'assemblies_count': len(assemblies),
                'has_aot': has_aot,
            }
        }

    # ---- Cordova / Ionic ----
    @staticmethod
    def _detect_cordova(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'www_dir': False,
            'cordova_js': False,
            'cordova_plugins': False,
            'ionic_config': False,
        }
        evidence = []
        framework = 'Cordova'
        plugins = []

        for idx, f in enumerate(all_lower):
            if 'assets/www/' in f:
                indicators['www_dir'] = True
            if f.endswith('/cordova.js') or f == 'cordova.js':
                indicators['cordova_js'] = True
                evidence.append(f"Encontrado cordova.js: {all_files[idx]}")
            if 'cordova_plugins.js' in f:
                indicators['cordova_plugins'] = True
                evidence.append(f"Encontrado cordova_plugins.js: {all_files[idx]}")
            if 'ionic.config.json' in f:
                indicators['ionic_config'] = True
                framework = 'Ionic'
                evidence.append(f"Encontrado ionic.config.json: {all_files[idx]}")

        # Also detect Capacitor
        for f in all_lower:
            if 'capacitor.config.json' in f or 'capacitor.plugins.json' in f:
                framework = 'Capacitor'
                evidence.append("Detectado Capacitor framework")
                indicators['www_dir'] = True
                break

        found = sum(1 for v in indicators.values() if v)
        if found == 0:
            return None

        if indicators['www_dir']:
            evidence.append("Directorio assets/www/ presente")

        confidence = 'High' if found >= 3 else ('Medium' if found >= 2 else 'Low')

        # Extract plugins from cordova_plugins.js
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if 'cordova_plugins.js' in name.lower():
                        try:
                            content = zf.read(name).decode('utf-8', errors='ignore')
                            plugin_matches = re.findall(
                                r'"id"\s*:\s*"([^"]+)"', content)
                            if plugin_matches:
                                plugins = plugin_matches
                                evidence.append(f"Plugins Cordova detectados: {len(plugins)}")
                                for p in plugins[:10]:
                                    evidence.append(f"  - Plugin: {p}")
                        except Exception:
                            pass
                        break
        except Exception:
            pass

        commands = [
            {
                'tool': 'extract_www',
                'command': f'unzip -o "{apk_path}" "assets/www/*" -d ./cordova_extracted/',
                'description': 'Extraer contenido web de Cordova/Ionic'
            },
        ]

        frida_hooks = [
            {
                'name': 'Cordova Bridge Hook',
                'description': 'Interceptar llamadas del bridge Cordova',
                'script': (
                    "// Frida hook para Cordova bridge\n"
                    "Java.perform(function() {\n"
                    "    try {\n"
                    "        var CordovaBridge = Java.use('org.apache.cordova.CordovaBridge');\n"
                    "        CordovaBridge.jsExec.overload('int', 'java.lang.String', 'java.lang.String', "
                    "'java.lang.String', 'java.lang.String').implementation = function(bridgeSecret, service, "
                    "action, callbackId, args) {\n"
                    "            console.log('[Cordova] Service=' + service + ' Action=' + action + ' Args=' + args);\n"
                    "            return this.jsExec(bridgeSecret, service, action, callbackId, args);\n"
                    "        };\n"
                    "    } catch(e) { console.log('[Cordova] Hook error: ' + e); }\n"
                    "});"
                )
            },
        ]

        return {
            'name': framework,
            'confidence': confidence,
            'version': None,
            'evidence': evidence,
            'analysis_commands': commands,
            'frida_hooks': frida_hooks,
            'details': {
                'framework_type': framework,
                'plugins_found': plugins,
            }
        }

    # ---- Kotlin Multiplatform ----
    @staticmethod
    def _detect_kotlin_multiplatform(apk_path, all_files, all_lower, decompiled_dir):
        indicators = {
            'kotlin_stdlib': False,
            'kotlinx': False,
            'libkotlin_so': False,
        }
        evidence = []

        for idx, f in enumerate(all_lower):
            if 'kotlin-stdlib' in f or 'kotlin/kotlin.kotlin_builtins' in f:
                indicators['kotlin_stdlib'] = True
            if 'kotlinx-' in f or 'kotlinx/' in f:
                indicators['kotlinx'] = True
            if f.startswith('lib/') and 'libkotlin' in f and f.endswith('.so'):
                indicators['libkotlin_so'] = True
                evidence.append(f"Encontrado native Kotlin lib: {all_files[idx]}")

        # KMP-specific signals
        kmp_signals = 0
        for f in all_lower:
            if 'kotlinx-serialization' in f:
                kmp_signals += 1
            if 'kotlinx-coroutines-core' in f:
                kmp_signals += 1
            if 'kotlin-multiplatform' in f or 'kmp' in f:
                kmp_signals += 2

        found = sum(1 for v in indicators.values() if v)
        # Kotlin stdlib alone is very common; need more signals for KMP
        if found == 0 or (found == 1 and indicators['kotlin_stdlib'] and kmp_signals == 0):
            return None

        if indicators['kotlin_stdlib']:
            evidence.append("Kotlin stdlib presente")
        if indicators['kotlinx']:
            evidence.append("Kotlinx libraries presentes")

        confidence = 'Medium' if (found >= 2 or kmp_signals >= 2) else 'Low'
        if indicators['libkotlin_so'] and found >= 2:
            confidence = 'High'

        return {
            'name': 'Kotlin Multiplatform',
            'confidence': confidence,
            'version': None,
            'evidence': evidence,
            'analysis_commands': [],
            'frida_hooks': [],
            'details': {
                'kmp_indicators': found + kmp_signals,
            }
        }


# ====================================================================
# MODULO: ANDROWARN - ANALISIS DE COMPORTAMIENTOS
# ====================================================================

class AndrowarnAnalyzer:
    """Análisis de comportamientos usando Androwarn (telefonía, PIM, audio/video, conexiones).

    Complementa Quark — Quark clasifica, Androwarn describe.
    """

    BEHAVIOR_CATEGORIES = [
        "telephony_identifiers_leakage",
        "device_settings_harvesting",
        "location_lookup",
        "connection_interfaces_exfiltration",
        "telephony_services_abuse",
        "audio_video_eavesdropping",
        "suspicious_connection_establishment",
        "PIM_data_leakage",
        "code_execution",
    ]

    # Mapping from androwarn dict keys to our category names
    _KEY_MAP = {
        "telephony_identifiers_leakage": "telephony_identifiers_leakage",
        "device_settings_harvesting": "device_settings_harvesting",
        "location_lookup": "location_lookup",
        "connection_interfaces_exfiltration": "connection_interfaces_exfiltration",
        "telephony_services_abuse": "telephony_services_abuse",
        "audio_video_eavesdropping": "audio_video_eavesdropping",
        "suspicious_connection_establishment": "suspicious_connection_establishment",
        "PIM_data_leakage": "PIM_data_leakage",
        "code_execution": "code_execution",
    }

    @staticmethod
    def analyze(apk_path):
        result = {
            "available": False,
            "behaviors": {},
            "total_behaviors": 0,
            "severity": "LIMPIO",
            "summary": "",
        }

        if not HAS_ANDROWARN:
            result["error"] = "Androwarn no instalado (pip install androwarn)"
            return result

        try:
            from androguard.misc import AnalyzeAPK
            a, d_list, dx = AnalyzeAPK(apk_path)
            # androwarn expects single DalvikVMFormat; use the first DEX
            d = d_list[0] if d_list else None
            if not d:
                result["error"] = "No se pudo obtener DalvikVMFormat del APK"
                return result

            analysis_data = _androwarn_perform(apk_path, a, d, dx, False)
            result["available"] = True

            # analysis_data is a list of dicts; flatten all entries
            total = 0
            merged = {}
            for entry in analysis_data:
                if isinstance(entry, dict):
                    for key, items in entry.items():
                        if isinstance(items, list):
                            findings = []
                            for item in items:
                                if isinstance(item, (list, tuple)) and len(item) >= 2:
                                    label, values = item[0], item[1]
                                    if isinstance(values, list) and values:
                                        findings.extend(values)
                                elif isinstance(item, str):
                                    findings.append(item)
                            if findings:
                                merged[key] = findings

            # Map to our categories
            category_keywords = {
                "telephony_identifiers_leakage": ["telephony_identifiers", "imei", "imsi", "phone_number"],
                "device_settings_harvesting": ["device_settings", "settings"],
                "location_lookup": ["location", "geolocation", "gps"],
                "connection_interfaces_exfiltration": ["connection_interfaces", "wifi", "bluetooth"],
                "telephony_services_abuse": ["telephony_services", "sms", "call"],
                "audio_video_eavesdropping": ["audio_video", "camera", "microphone", "record"],
                "suspicious_connection_establishment": ["remote_connection", "connection_establishment", "url", "http", "socket"],
                "PIM_data_leakage": ["PIM", "pim", "contacts", "calendar", "sms_content"],
                "code_execution": ["code_execution", "exec", "runtime", "native_code"],
            }

            for cat in AndrowarnAnalyzer.BEHAVIOR_CATEGORIES:
                keywords = category_keywords.get(cat, [cat])
                cat_findings = []
                for data_key, data_vals in merged.items():
                    if any(kw.lower() in data_key.lower() for kw in keywords):
                        cat_findings.extend(data_vals[:20])
                if cat_findings:
                    result["behaviors"][cat] = {
                        "count": len(cat_findings),
                        "details": cat_findings[:20],
                    }
                    total += len(cat_findings)

            result["total_behaviors"] = total

            # Clasificar severidad
            critical_cats = {"telephony_services_abuse", "audio_video_eavesdropping",
                           "code_execution", "suspicious_connection_establishment"}
            has_critical = any(c in result["behaviors"] for c in critical_cats)

            if has_critical and total > 10:
                result["severity"] = "CRITICO"
            elif has_critical or total > 8:
                result["severity"] = "ALTO"
            elif total > 4:
                result["severity"] = "MEDIO"
            elif total > 0:
                result["severity"] = "BAJO"

            result["summary"] = (
                f"Androwarn: {total} comportamientos en {len(result['behaviors'])} categorías. "
                f"Severidad: {result['severity']}"
            )

        except Exception as e:
            result["error"] = f"Error en análisis Androwarn: {e}"
            logger.error(f"Androwarn error: {e}")

        return result


# ====================================================================
# MODULO: FUZZY HASHING - SSDEEP + TLSH
# ====================================================================

class FuzzyHasher:
    """Fuzzy hashing con ssdeep y TLSH para detección de variantes/campañas.

    Estándar DFIR. Permite correlacionar APKs sospechosos entre análisis.
    """

    @staticmethod
    def analyze(apk_path):
        result = {
            "available": False,
            "apk_hashes": {},
            "dex_hashes": [],
            "has_ssdeep": HAS_SSDEEP,
            "has_tlsh": HAS_TLSH,
        }

        if not HAS_SSDEEP and not HAS_TLSH:
            result["error"] = "Ni ssdeep ni tlsh instalados (pip install ssdeep python-tlsh)"
            return result

        result["available"] = True

        try:
            # Hash del APK completo
            apk_hashes = {}
            if HAS_SSDEEP:
                apk_hashes["ssdeep"] = ssdeep.hash_from_file(apk_path)
            if HAS_TLSH:
                apk_hashes["tlsh"] = tlsh.hash(open(apk_path, 'rb').read())
            result["apk_hashes"] = apk_hashes

            # Hash de cada DEX dentro del APK
            dex_hashes = []
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    dex_files = [n for n in zf.namelist() if n.endswith('.dex')]
                    for dex_name in dex_files:
                        dex_data = zf.read(dex_name)
                        dex_entry = {"file": dex_name, "size": len(dex_data)}
                        if HAS_SSDEEP:
                            dex_entry["ssdeep"] = ssdeep.hash(dex_data)
                        if HAS_TLSH:
                            try:
                                dex_entry["tlsh"] = tlsh.hash(dex_data)
                            except ValueError:
                                dex_entry["tlsh"] = "N/A (archivo muy pequeño)"
                        dex_hashes.append(dex_entry)
            except zipfile.BadZipFile:
                pass

            result["dex_hashes"] = dex_hashes

        except Exception as e:
            result["error"] = f"Error calculando fuzzy hashes: {e}"
            logger.error(f"FuzzyHasher error: {e}")

        return result


# ====================================================================
# MODULO: ENTROPY + OBFUSCATION SCORING
# ====================================================================

class EntropyObfuscationAnalyzer:
    """Análisis de entropía Shannon por archivo + scoring de ofuscación.

    Detecta packing (entropía > 7.5) y ofuscación ProGuard/R8/DexGuard
    (ratio de nombres cortos, entropía de identificadores). Pure Python, sin deps.
    """

    ENTROPY_PACKED_THRESHOLD = 7.5
    SHORT_NAME_THRESHOLD = 0.6  # >60% de nombres <=2 chars sugiere ofuscación

    @staticmethod
    def _shannon_entropy(data):
        """Calcula entropía Shannon de bytes."""
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _identifier_entropy(names):
        """Calcula entropía de una lista de identificadores (nombres de clase/método)."""
        if not names:
            return 0.0
        all_chars = ''.join(names)
        if not all_chars:
            return 0.0
        freq = defaultdict(int)
        for c in all_chars:
            freq[c] += 1
        length = len(all_chars)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def analyze(apk_path):
        result = {
            "available": True,
            "file_entropies": [],
            "packed_files": [],
            "obfuscation_score": 0,
            "obfuscation_indicators": [],
            "overall_entropy": 0.0,
            "dex_analysis": [],
            "summary": "",
        }

        try:
            entropies = []
            packed = []

            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    if info.file_size < 100:
                        continue
                    try:
                        data = zf.read(info.filename)
                        ent = EntropyObfuscationAnalyzer._shannon_entropy(data)
                        entry = {
                            "file": info.filename,
                            "size": info.file_size,
                            "entropy": round(ent, 4),
                        }
                        entropies.append(entry)
                        if ent > EntropyObfuscationAnalyzer.ENTROPY_PACKED_THRESHOLD:
                            entry["packed"] = True
                            packed.append(entry)
                    except Exception:
                        continue

            # Top 30 por entropía
            entropies.sort(key=lambda x: x["entropy"], reverse=True)
            result["file_entropies"] = entropies[:30]
            result["packed_files"] = packed

            if entropies:
                result["overall_entropy"] = round(
                    sum(e["entropy"] for e in entropies) / len(entropies), 4)

            # Análisis de ofuscación en DEX
            obf_score = 0
            obf_indicators = []

            with zipfile.ZipFile(apk_path, 'r') as zf:
                dex_files = [n for n in zf.namelist() if n.endswith('.dex')]
                for dex_name in dex_files:
                    dex_data = zf.read(dex_name)
                    dex_ent = EntropyObfuscationAnalyzer._shannon_entropy(dex_data)
                    dex_info = {
                        "file": dex_name,
                        "entropy": round(dex_ent, 4),
                        "short_names_ratio": 0.0,
                        "identifier_entropy": 0.0,
                    }

                    # Extraer strings del DEX para análisis de ofuscación
                    class_names = []
                    try:
                        # Buscar patrones de nombres de clase en el DEX
                        text = dex_data.decode('utf-8', errors='ignore')
                        # Nombres de clase en formato Lcom/...;
                        import re as _re
                        class_refs = _re.findall(r'L([a-zA-Z0-9/$_]+);', text)
                        for ref in class_refs:
                            parts = ref.split('/')
                            if parts:
                                class_names.append(parts[-1].split('$')[0])
                    except Exception:
                        pass

                    if class_names:
                        short_count = sum(1 for n in class_names if len(n) <= 2)
                        short_ratio = short_count / len(class_names) if class_names else 0
                        dex_info["short_names_ratio"] = round(short_ratio, 4)
                        dex_info["identifier_entropy"] = round(
                            EntropyObfuscationAnalyzer._identifier_entropy(class_names), 4)
                        dex_info["unique_names"] = len(set(class_names))

                        if short_ratio > EntropyObfuscationAnalyzer.SHORT_NAME_THRESHOLD:
                            obf_score += 30
                            obf_indicators.append(
                                f"{dex_name}: {short_ratio:.0%} nombres cortos (≤2 chars) - "
                                f"probable ProGuard/R8")

                        # Entropía baja de identificadores = nombres predecibles = ofuscación
                        if dex_info["identifier_entropy"] < 3.0 and len(class_names) > 50:
                            obf_score += 15
                            obf_indicators.append(
                                f"{dex_name}: entropía de identificadores baja "
                                f"({dex_info['identifier_entropy']:.2f}) - ofuscación de renombrado")

                    if dex_ent > 6.5:
                        obf_score += 10
                        obf_indicators.append(
                            f"{dex_name}: entropía alta ({dex_ent:.2f}) - posible cifrado/packing")

                    result["dex_analysis"].append(dex_info)

            # Archivos packed suman al score
            if len(packed) > 3:
                obf_score += 15
                obf_indicators.append(f"{len(packed)} archivos con entropía > 7.5 (packing)")

            result["obfuscation_score"] = min(obf_score, 100)
            result["obfuscation_indicators"] = obf_indicators

            level = "Ninguna"
            if obf_score >= 60:
                level = "Fuerte (DexGuard/cifrado)"
            elif obf_score >= 30:
                level = "Moderada (ProGuard/R8)"
            elif obf_score > 0:
                level = "Leve"

            result["summary"] = (
                f"Entropía media: {result['overall_entropy']:.2f}, "
                f"{len(packed)} archivos empaquetados, "
                f"Ofuscación: {level} (score: {obf_score}/100)"
            )

        except Exception as e:
            result["available"] = False
            result["error"] = f"Error en análisis de entropía: {e}"
            logger.error(f"EntropyObfuscation error: {e}")

        return result


# ====================================================================
# MODULO: MITRE ATT&CK FOR MOBILE MAPPING
# ====================================================================

class MitreAttackMobile:
    """Mapea hallazgos de todos los módulos a técnicas MITRE ATT&CK for Mobile.

    Referencia: https://attack.mitre.org/matrices/mobile/
    """

    # Mapeo de permisos a técnicas MITRE
    PERMISSION_TECHNIQUES = {
        "android.permission.READ_SMS": ("T1636.004", "Protected User Data: SMS Messages"),
        "android.permission.SEND_SMS": ("T1582.001", "SMS Control"),
        "android.permission.READ_CONTACTS": ("T1636.003", "Protected User Data: Contact List"),
        "android.permission.READ_CALL_LOG": ("T1636.002", "Protected User Data: Call Log"),
        "android.permission.CAMERA": ("T1512", "Video Capture"),
        "android.permission.RECORD_AUDIO": ("T1429", "Audio Capture"),
        "android.permission.ACCESS_FINE_LOCATION": ("T1430", "Location Tracking"),
        "android.permission.ACCESS_COARSE_LOCATION": ("T1430", "Location Tracking"),
        "android.permission.READ_EXTERNAL_STORAGE": ("T1533", "Data from Local System"),
        "android.permission.WRITE_EXTERNAL_STORAGE": ("T1533", "Data from Local System"),
        "android.permission.INTERNET": ("T1071", "Application Layer Protocol"),
        "android.permission.ACCESS_WIFI_STATE": ("T1422", "System Network Configuration Discovery"),
        "android.permission.READ_PHONE_STATE": ("T1426", "System Information Discovery"),
        "android.permission.RECEIVE_BOOT_COMPLETED": ("T1398", "Boot or Logon Initialization Scripts"),
        "android.permission.INSTALL_PACKAGES": ("T1407", "Download New Code at Runtime"),
        "android.permission.REQUEST_INSTALL_PACKAGES": ("T1407", "Download New Code at Runtime"),
        "android.permission.SYSTEM_ALERT_WINDOW": ("T1411", "Input Prompt"),
        "android.permission.BIND_ACCESSIBILITY_SERVICE": ("T1453", "Abuse Accessibility Features"),
        "android.permission.BIND_DEVICE_ADMIN": ("T1401", "Device Administrator Permissions"),
        "android.permission.USE_BIOMETRIC": ("T1417", "Input Capture"),
    }

    # Mapeo de comportamientos Smali a técnicas
    SMALI_TECHNIQUES = {
        "Runtime.exec": ("T1623.001", "Command and Scripting Interpreter: Unix Shell"),
        "DexClassLoader": ("T1407", "Download New Code at Runtime"),
        "ProcessBuilder": ("T1623.001", "Command and Scripting Interpreter: Unix Shell"),
        "Cipher": ("T1521", "Encrypted Channel"),
        "HttpURLConnection": ("T1071.001", "Web Protocols"),
        "WebView.loadUrl": ("T1456", "Drive-By Compromise"),
        "PackageManager.getInstalledPackages": ("T1418", "Software Discovery"),
        "TelephonyManager.getDeviceId": ("T1426", "System Information Discovery"),
        "SmsManager": ("T1582.001", "SMS Control"),
        "ContentResolver": ("T1636", "Protected User Data"),
        "MediaRecorder": ("T1429", "Audio Capture"),
        "LocationManager": ("T1430", "Location Tracking"),
        "KeyLogger": ("T1417", "Input Capture"),
        "AccessibilityService": ("T1453", "Abuse Accessibility Features"),
        "reflection": ("T1620", "Reflective Code Loading"),
    }

    # Mapeo de categorías Quark a técnicas
    QUARK_BEHAVIOR_TECHNIQUES = {
        "SMS Abuse": ("T1582.001", "SMS Control"),
        "Location Tracking": ("T1430", "Location Tracking"),
        "Surveillance": ("T1512", "Video Capture"),
        "Contact/Call Abuse": ("T1636.003", "Protected User Data: Contact List"),
        "File Operations": ("T1533", "Data from Local System"),
        "Network Activity": ("T1071", "Application Layer Protocol"),
        "Code Execution": ("T1623", "Command and Scripting Interpreter"),
        "Cryptographic Ops": ("T1521", "Encrypted Channel"),
        "Evasion/Stealth": ("T1630", "Indicator Removal on Host"),
        "Device Fingerprinting": ("T1426", "System Information Discovery"),
    }

    @staticmethod
    def analyze(data):
        """Analiza todos los hallazgos y mapea a MITRE ATT&CK for Mobile."""
        result = {
            "available": True,
            "techniques": {},  # id -> {name, sources, evidence}
            "tactics": defaultdict(list),
            "total_techniques": 0,
            "coverage_summary": {},
            "summary": "",
        }

        techniques = {}

        def add_technique(tid, name, source, evidence=""):
            if tid not in techniques:
                techniques[tid] = {"id": tid, "name": name, "sources": [], "evidence": []}
            if source not in techniques[tid]["sources"]:
                techniques[tid]["sources"].append(source)
            if evidence and evidence not in techniques[tid]["evidence"]:
                techniques[tid]["evidence"].append(evidence[:200])

        # 1. Permisos -> MITRE
        manifest = data.get("manifest", {})
        for perm in manifest.get("permissions", []):
            if perm in MitreAttackMobile.PERMISSION_TECHNIQUES:
                tid, name = MitreAttackMobile.PERMISSION_TECHNIQUES[perm]
                add_technique(tid, name, "Permiso", perm.split('.')[-1])

        # 2. Smali -> MITRE
        smali = data.get("smali_analysis", {})
        for pattern_name in smali.get("grouped", {}):
            for smali_key, (tid, name) in MitreAttackMobile.SMALI_TECHNIQUES.items():
                if smali_key.lower() in pattern_name.lower():
                    add_technique(tid, name, "Smali", pattern_name)

        # 3. Quark behaviors -> MITRE
        quark = data.get("quark", {})
        if quark.get("available"):
            for behavior in quark.get("behaviors_detected", []):
                bname = behavior.get("behavior", "")
                if bname in MitreAttackMobile.QUARK_BEHAVIOR_TECHNIQUES:
                    tid, name = MitreAttackMobile.QUARK_BEHAVIOR_TECHNIQUES[bname]
                    rules = [r["crime"][:80] for r in behavior.get("rules", [])[:3]]
                    add_technique(tid, name, "Quark", "; ".join(rules))

        # 4. Androwarn -> MITRE
        androwarn = data.get("androwarn", {})
        if androwarn.get("available"):
            androwarn_map = {
                "telephony_identifiers_leakage": ("T1426", "System Information Discovery"),
                "telephony_services_abuse": ("T1582.001", "SMS Control"),
                "audio_video_eavesdropping": ("T1429", "Audio Capture"),
                "location_lookup": ("T1430", "Location Tracking"),
                "PIM_data_leakage": ("T1636", "Protected User Data"),
                "suspicious_connection_establishment": ("T1071", "Application Layer Protocol"),
                "code_execution": ("T1623", "Command and Scripting Interpreter"),
                "connection_interfaces_exfiltration": ("T1048", "Exfiltration Over Alternative Protocol"),
            }
            for cat, bdata in androwarn.get("behaviors", {}).items():
                if cat in androwarn_map:
                    tid, name = androwarn_map[cat]
                    add_technique(tid, name, "Androwarn", f"{cat}: {bdata.get('count', 0)} hallazgos")

        # 5. APKiD -> MITRE
        apkid = data.get("apkid", {})
        if apkid.get("available"):
            if apkid.get("packers"):
                add_technique("T1406", "Obfuscated Files or Information", "APKiD",
                            f"{len(apkid['packers'])} packers")
            if apkid.get("anti_analysis"):
                add_technique("T1627", "Execution Guardrails", "APKiD",
                            f"{len(apkid['anti_analysis'])} anti-análisis")

        # 6. Entropy/obfuscation -> MITRE
        entropy = data.get("entropy_obfuscation", {})
        if entropy.get("available"):
            if entropy.get("obfuscation_score", 0) >= 30:
                add_technique("T1406", "Obfuscated Files or Information", "Entropía",
                            f"Score: {entropy['obfuscation_score']}/100")
            if entropy.get("packed_files"):
                add_technique("T1406.001", "Software Packing", "Entropía",
                            f"{len(entropy['packed_files'])} archivos packed")

        result["techniques"] = techniques
        result["total_techniques"] = len(techniques)

        # Clasificar por tácticas
        tactic_map = {
            "T1430": "Collection", "T1429": "Collection", "T1512": "Collection",
            "T1533": "Collection", "T1636": "Collection", "T1417": "Collection",
            "T1071": "Command and Control", "T1521": "Command and Control",
            "T1048": "Exfiltration",
            "T1407": "Defense Evasion", "T1406": "Defense Evasion",
            "T1627": "Defense Evasion", "T1630": "Defense Evasion",
            "T1620": "Defense Evasion",
            "T1623": "Execution", "T1582": "Initial Access", "T1456": "Initial Access",
            "T1422": "Discovery", "T1426": "Discovery", "T1418": "Discovery",
            "T1398": "Persistence", "T1401": "Persistence",
            "T1411": "Credential Access", "T1453": "Credential Access",
        }
        for tid, tech in techniques.items():
            base_tid = tid.split('.')[0]
            tactic = tactic_map.get(base_tid, "Other")
            result["tactics"][tactic].append(tid)

        result["coverage_summary"] = {
            tactic: len(tids) for tactic, tids in result["tactics"].items()
        }

        result["summary"] = (
            f"MITRE ATT&CK: {len(techniques)} técnicas mapeadas en "
            f"{len(result['tactics'])} tácticas. "
            f"Top: {', '.join(sorted(result['tactics'].keys(), key=lambda t: -len(result['tactics'][t]))[:3])}"
        )

        return result


# ====================================================================
# MODULO: FORENSIC TIMELINE BUILDER
# ====================================================================

class ForensicTimeline:
    """Consolida todos los timestamps en cronología forense.

    Pilar de todo análisis DFIR: cert dates, build times, asset timestamps,
    DEX compilation dates. Detecta inconsistencias temporales.
    """

    @staticmethod
    def analyze(apk_path, data):
        result = {
            "available": True,
            "events": [],
            "inconsistencies": [],
            "time_range": {},
            "summary": "",
        }

        events = []

        try:
            # 1. Timestamps del certificado
            cert = data.get("certificate", {})
            signer = cert.get("signer_info", {})
            if signer.get("valid_from"):
                events.append({
                    "timestamp": signer["valid_from"],
                    "source": "Certificado",
                    "event": "Inicio de validez del certificado",
                    "category": "signing",
                })
            if signer.get("valid_until"):
                events.append({
                    "timestamp": signer["valid_until"],
                    "source": "Certificado",
                    "event": "Fin de validez del certificado",
                    "category": "signing",
                })

            # Certificado profundo
            crypto_cert = data.get("crypto_cert", {})
            for ci in crypto_cert.get("certificates", []):
                if ci.get("not_before"):
                    events.append({
                        "timestamp": ci["not_before"],
                        "source": "X.509",
                        "event": f"Cert not_before ({ci.get('file','')})",
                        "category": "signing",
                    })
                if ci.get("not_after"):
                    events.append({
                        "timestamp": ci["not_after"],
                        "source": "X.509",
                        "event": f"Cert not_after ({ci.get('file','')})",
                        "category": "signing",
                    })

            # 2. Timestamps de archivos dentro del ZIP
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    for info in zf.infolist():
                        if info.date_time and info.date_time[0] > 1980:
                            try:
                                dt = datetime(*info.date_time)
                                ts = dt.strftime('%Y-%m-%d %H:%M:%S')
                                events.append({
                                    "timestamp": ts,
                                    "source": "ZIP entry",
                                    "event": f"Archivo: {info.filename}",
                                    "category": "build",
                                })
                            except (ValueError, TypeError):
                                continue
            except zipfile.BadZipFile:
                pass

            # 3. Timestamp del propio APK en disco
            try:
                apk_mtime = os.path.getmtime(apk_path)
                apk_dt = datetime.fromtimestamp(apk_mtime)
                events.append({
                    "timestamp": apk_dt.strftime('%Y-%m-%d %H:%M:%S'),
                    "source": "Filesystem",
                    "event": "Fecha de modificación del APK",
                    "category": "filesystem",
                })
            except OSError:
                pass

            # Ordenar cronológicamente
            def _parse_ts(ts_str):
                for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S',
                           '%b %d %H:%M:%S %Y %Z', '%a %b %d %H:%M:%S %Z %Y'):
                    try:
                        return datetime.strptime(ts_str, fmt)
                    except (ValueError, TypeError):
                        continue
                return None

            parseable_events = []
            for ev in events:
                dt = _parse_ts(ev["timestamp"])
                if dt:
                    ev["_dt"] = dt
                    parseable_events.append(ev)

            parseable_events.sort(key=lambda x: x["_dt"])

            # Detectar inconsistencias
            inconsistencies = []

            # Cert firmado después del build más antiguo
            cert_dates = [e for e in parseable_events if e["category"] == "signing" and "Inicio" in e["event"]]
            build_dates = [e for e in parseable_events if e["category"] == "build"]

            if cert_dates and build_dates:
                earliest_build = min(e["_dt"] for e in build_dates)
                for cd in cert_dates:
                    if cd["_dt"] > earliest_build:
                        inconsistencies.append({
                            "type": "CERT_POST_BUILD",
                            "severity": "ALTO",
                            "description": (
                                f"Certificado ({cd['timestamp']}) es posterior al build más antiguo "
                                f"({earliest_build.strftime('%Y-%m-%d %H:%M:%S')})"
                            ),
                        })

            # Archivos con timestamps muy dispersos (>5 años de rango)
            if len(build_dates) > 2:
                min_dt = min(e["_dt"] for e in build_dates)
                max_dt = max(e["_dt"] for e in build_dates)
                range_days = (max_dt - min_dt).days
                if range_days > 1825:  # >5 años
                    inconsistencies.append({
                        "type": "WIDE_TIME_RANGE",
                        "severity": "MEDIO",
                        "description": (
                            f"Rango de timestamps de archivos: {range_days} días "
                            f"({min_dt.strftime('%Y-%m-%d')} a {max_dt.strftime('%Y-%m-%d')})"
                        ),
                    })

            # Timestamps futuros
            now = datetime.now()
            future_events = [e for e in parseable_events if e["_dt"] > now and e["category"] == "build"]
            if future_events:
                inconsistencies.append({
                    "type": "FUTURE_TIMESTAMPS",
                    "severity": "ALTO",
                    "description": f"{len(future_events)} archivos con timestamps en el futuro",
                })

            # Timestamps epoch (1970-01-01 o 1980-01-01)
            epoch_events = [e for e in parseable_events if e["_dt"].year <= 1980]
            if epoch_events:
                inconsistencies.append({
                    "type": "EPOCH_TIMESTAMPS",
                    "severity": "BAJO",
                    "description": f"{len(epoch_events)} archivos con timestamp epoch (posible packing/manipulación)",
                })

            # Limpiar el campo interno _dt
            for ev in parseable_events:
                del ev["_dt"]

            result["events"] = parseable_events[:100]  # Limitar a 100 eventos
            result["inconsistencies"] = inconsistencies

            if parseable_events:
                result["time_range"] = {
                    "earliest": parseable_events[0]["timestamp"],
                    "latest": parseable_events[-1]["timestamp"],
                    "total_events": len(parseable_events),
                }

            result["summary"] = (
                f"Timeline: {len(parseable_events)} eventos, "
                f"{len(inconsistencies)} inconsistencias. "
                f"Rango: {result['time_range'].get('earliest', 'N/A')} - "
                f"{result['time_range'].get('latest', 'N/A')}"
            )

        except Exception as e:
            result["available"] = False
            result["error"] = f"Error construyendo timeline: {e}"
            logger.error(f"ForensicTimeline error: {e}")

        return result


class RiskScorer:
    @staticmethod
    def calculate(manifest, cert, network, secrets, smali, structure,
                  androguard=None, quark=None, yara_results=None, apkid=None,
                  lief_results=None, endpoints=None, injection=None, crypto_cert=None,
                  forensic_db=None, framework=None, banking=None, anticheat=None,
                  androwarn=None, entropy_obfuscation=None, mitre=None, timeline=None,
                  backdoor_c2=None, endpoint_classification=None, exfiltration=None,
                  string_deobfuscation=None, signature_scheme=None, deep_resources=None,
                  accessibility_overlay=None, intent_ipc=None, owasp_mobile=None):
        score = 0
        findings = []

        # Permisos peligrosos
        for pd in manifest.get("dangerous_permission_details", []):
            sev = pd["severity"]
            if sev == "CRITICO":
                score += 15
                findings.append(("CRITICO", f"Permiso: {pd['permission']} - {pd['description']}"))
            elif sev == "ALTO":
                score += 8
                findings.append(("ALTO", f"Permiso: {pd['permission']} - {pd['description']}"))
            elif sev == "MEDIO":
                score += 3
                findings.append(("MEDIO", f"Permiso: {pd['permission']} - {pd['description']}"))

        # Flags
        flags = manifest.get("flags", {})
        if flags.get("debuggable"):
            score += 25
            findings.append(("CRITICO", "App marcada como debuggable"))
        if flags.get("allowBackup"):
            score += 10
            findings.append(("ALTO", "allowBackup habilitado - datos extraibles"))
        if flags.get("usesCleartextTraffic"):
            score += 12
            findings.append(("ALTO", "Trafico HTTP sin cifrar permitido"))

        # Componentes exportados sin proteccion
        unprotected = [c for c in manifest.get("exported_components", []) if not c.get("protected")]
        if unprotected:
            score += min(len(unprotected) * 3, 20)
            findings.append(("ALTO", f"{len(unprotected)} componentes exportados sin proteccion"))

        # SDK antiguo
        min_sdk = manifest.get("min_sdk", "")
        if min_sdk and min_sdk.isdigit() and int(min_sdk) < 21:
            score += 8
            findings.append(("MEDIO", f"minSdkVersion={min_sdk} (Android < 5.0)"))
        target_sdk = manifest.get("target_sdk", "")
        if target_sdk and target_sdk.isdigit() and int(target_sdk) < 28:
            score += 5
            findings.append(("MEDIO", f"targetSdkVersion={target_sdk} (< Android 9)"))

        # Certificado
        if not cert.get("is_signed"):
            score += 20
            findings.append(("CRITICO", "APK no firmado"))
        alg = cert.get("signer_info", {}).get("algorithm", "").lower()
        if "sha1" in alg and "sha256" not in alg:
            score += 5
            findings.append(("MEDIO", "Certificado con SHA1 (depreciado)"))

        # Red
        if network.get("cleartext_permitted"):
            score += 10
            findings.append(("ALTO", "network_security_config permite cleartext"))
        if network.get("trust_user_certs"):
            score += 15
            findings.append(("CRITICO", "App confia en certificados de usuario"))
        if network.get("certificate_pinning"):
            score -= 5
            findings.append(("INFO", "Certificate pinning detectado (buena practica)"))

        # Secretos
        secret_dict = secrets if isinstance(secrets, dict) else {}
        for stype in ["AWS_Key", "Google_API_Key", "Private_Key", "Hardcoded_Password",
                       "JWT_Token", "Connection_String", "Telegram_Bot", "GitHub_Token"]:
            items = secret_dict.get(stype, [])
            if items:
                score += min(len(items) * 10, 25)
                findings.append(("CRITICO", f"{len(items)} {stype} hardcodeado(s)"))

        ips = secret_dict.get("IP_Address", [])
        if ips:
            score += min(len(ips) * 2, 10)
            findings.append(("MEDIO", f"{len(ips)} IPs hardcodeadas"))

        # Codigo Smali
        for name, info in smali.get("grouped", {}).items():
            sev = info.get("severity", "")
            if sev == "CRITICO":
                score += 12
                findings.append(("CRITICO", f"Codigo: {info['description']} ({info['count']} ocurrencias)"))
            elif sev == "ALTO":
                score += 6
                findings.append(("ALTO", f"Codigo: {info['description']} ({info['count']} ocurrencias)"))
            elif sev == "MEDIO":
                score += 2

        # Estructura
        if structure.get("suspicious_assets"):
            score += min(len(structure["suspicious_assets"]) * 5, 20)
            findings.append(("ALTO", f"{len(structure['suspicious_assets'])} assets sospechosos"))

        dex_count = len(structure.get("dex_files", []))
        if dex_count > 3:
            score += 3
            findings.append(("INFO", f"MultiDex: {dex_count} archivos DEX"))

        # Androguard: APIs peligrosas
        if androguard and androguard.get("available"):
            api_calls = androguard.get("dangerous_api_calls", [])
            critico_apis = [a for a in api_calls if a.get("severity") == "CRITICO"]
            alto_apis = [a for a in api_calls if a.get("severity") == "ALTO"]
            if critico_apis:
                score += min(len(critico_apis) * 8, 20)
                findings.append(("CRITICO", f"Androguard: {len(critico_apis)} APIs criticas detectadas ({', '.join(a['description'][:30] for a in critico_apis[:3])})"))
            if alto_apis:
                score += min(len(alto_apis) * 4, 15)
                findings.append(("ALTO", f"Androguard: {len(alto_apis)} APIs de alto riesgo"))

        # Quark-Engine: clasificación de amenaza
        if quark and quark.get("available"):
            q_level = quark.get("threat_level", "")
            q_matched = len(quark.get("rules_matched", []))
            q_behaviors = quark.get("behaviors_detected", [])
            if q_level == "CRITICO":
                score += 25
                findings.append(("CRITICO", f"Quark-Engine: Probable MALWARE ({q_matched} reglas, comportamientos: {', '.join(b['behavior'] for b in q_behaviors[:4])})"))
            elif q_level == "ALTO":
                score += 15
                findings.append(("ALTO", f"Quark-Engine: Comportamiento sospechoso ({q_matched} reglas)"))
            elif q_level == "MEDIO":
                score += 8
                findings.append(("MEDIO", f"Quark-Engine: Actividad cuestionable ({q_matched} reglas)"))
            elif q_level == "BAJO":
                score += 3
                findings.append(("BAJO", f"Quark-Engine: Riesgo menor ({q_matched} reglas)"))
            elif q_level == "LIMPIO":
                score -= 3
                findings.append(("INFO", f"Quark-Engine: Sin malware detectado ({quark.get('rules_scanned',0)} reglas escaneadas)"))

        # YARA: coincidencias de reglas
        if yara_results and yara_results.get("available"):
            yara_matches = yara_results.get("matches", [])
            for ym in yara_matches:
                ysev = ym.get("severity", "MEDIO")
                if ysev == "CRITICO":
                    score += 15
                    findings.append(("CRITICO", f"YARA: {ym['description']} (regla: {ym['rule']})"))
                elif ysev == "ALTO":
                    score += 8
                    findings.append(("ALTO", f"YARA: {ym['description']}"))
                elif ysev == "MEDIO":
                    score += 4
                    findings.append(("MEDIO", f"YARA: {ym['description']}"))

        # APKiD: packers y ofuscadores
        if apkid and apkid.get("available"):
            if apkid.get("packers"):
                score += min(len(apkid["packers"]) * 10, 20)
                findings.append(("ALTO", f"APKiD: {len(apkid['packers'])} packer(s) detectado(s): {', '.join(d['value'][:30] for d in apkid['packers'][:3])}"))
            if apkid.get("anti_analysis"):
                score += min(len(apkid["anti_analysis"]) * 5, 15)
                findings.append(("ALTO", f"APKiD: {len(apkid['anti_analysis'])} técnica(s) anti-análisis"))
            if apkid.get("protectors"):
                score += min(len(apkid["protectors"]) * 6, 12)
                findings.append(("MEDIO", f"APKiD: {len(apkid['protectors'])} protector(es)"))

        # LIEF: imports peligrosos en librerías nativas
        if lief_results and lief_results.get("available"):
            lief_criticos = [i for i in lief_results.get("dangerous_imports_found", []) if i.get("severity") == "CRITICO"]
            lief_altos = [i for i in lief_results.get("dangerous_imports_found", []) if i.get("severity") == "ALTO"]
            if lief_criticos:
                score += min(len(lief_criticos) * 8, 20)
                funcs = ', '.join(set(i['function'] for i in lief_criticos[:4]))
                findings.append(("CRITICO", f"LIEF: {len(lief_criticos)} imports nativos críticos ({funcs})"))
            if lief_altos:
                score += min(len(lief_altos) * 4, 12)
                findings.append(("ALTO", f"LIEF: {len(lief_altos)} imports nativos de alto riesgo"))
            if lief_results.get("suspicious_libs"):
                score += 10
                findings.append(("ALTO", f"LIEF: {len(lief_results['suspicious_libs'])} lib(s) nativa(s) sospechosa(s)"))

        # Endpoints: URLs y APIs extraidos
        if endpoints and endpoints.get("available"):
            internal_ips = endpoints.get("endpoints_by_type", {}).get("internal_ips", [])
            if internal_ips:
                score += min(len(internal_ips) * 8, 15)
                findings.append(("CRITICO", f"Endpoints: {len(internal_ips)} IP(s) internas hardcodeadas"))
            cloud = endpoints.get("endpoints_by_type", {}).get("cloud_resources", [])
            if cloud:
                score += min(len(cloud) * 5, 10)
                findings.append(("ALTO", f"Endpoints: {len(cloud)} recurso(s) cloud expuesto(s)"))
            auth = endpoints.get("endpoints_by_type", {}).get("auth_endpoints", [])
            if auth:
                score += min(len(auth) * 3, 8)
                findings.append(("ALTO", f"Endpoints: {len(auth)} endpoint(s) de autenticación"))

        # Inyeccion: vulnerabilidades detectadas
        if injection and injection.get("available"):
            inj_criticos = injection.get("by_severity", {}).get("CRITICO", [])
            inj_altos = injection.get("by_severity", {}).get("ALTO", [])
            if inj_criticos:
                score += min(len(inj_criticos) * 12, 30)
                types = ', '.join(set(v.get('type','') for v in inj_criticos[:3]))
                findings.append(("CRITICO", f"Inyección: {len(inj_criticos)} vulnerabilidad(es) críticas ({types})"))
            if inj_altos:
                score += min(len(inj_altos) * 6, 18)
                findings.append(("ALTO", f"Inyección: {len(inj_altos)} vulnerabilidad(es) de alto riesgo"))
            if injection.get("exported_attack_surface"):
                score += min(len(injection["exported_attack_surface"]) * 5, 15)
                findings.append(("ALTO", f"Inyección: {len(injection['exported_attack_surface'])} componente(s) exportado(s) vulnerable(s)"))

        # Certificado profundo (cryptography)
        if crypto_cert and crypto_cert.get("available"):
            for anomaly in crypto_cert.get("cert_anomalies", []):
                if "debug" in anomaly.lower() or "expirado" in anomaly.lower():
                    score += 10
                    findings.append(("ALTO", f"Cert: {anomaly}"))
                elif "md5" in anomaly.lower() or "inseguro" in anomaly.lower():
                    score += 8
                    findings.append(("CRITICO", f"Cert: {anomaly}"))
                elif "sha1" in anomaly.lower() or "depreciado" in anomaly.lower():
                    score += 4
                    findings.append(("MEDIO", f"Cert: {anomaly}"))
                else:
                    score += 2
                    findings.append(("MEDIO", f"Cert: {anomaly}"))

        # --- Nuevos módulos Tier 3 ---

        # Forensic DB findings
        if forensic_db and forensic_db.get("available"):
            for db in forensic_db.get("databases", []):
                risk_level = db.get("risk_level", "")
                enc_status = db.get("encryption_status", "")
                if risk_level == "High" or "unencrypted" in enc_status.lower():
                    score += 5
                    ev = db.get('evidence', {})
                    ev_str = ev.get('string_found', str(ev)) if isinstance(ev, dict) else str(ev)
                    findings.append(("ALTO", f"DB {db.get('type','?')} sin cifrado: {ev_str[:80]}"))
            for pin in forensic_db.get("cert_pinning_analysis", []):
                if pin.get("bypass_difficulty") == "Easy":
                    score += 8
                    findings.append(("ALTO", f"Cert pinning bypass fácil: {pin.get('type','')}"))

        # Framework-specific risks
        if framework and framework.get("available"):
            for fw in framework.get("detected_frameworks", []):
                name = fw.get("name", "")
                if name == "React Native" and fw.get("evidence", {}).get("has_source_maps"):
                    score += 12
                    findings.append(("ALTO", "React Native source maps expuestos"))
                if name == "Flutter" and fw.get("confidence") == "High":
                    score += 2
                    findings.append(("INFO", f"Framework Flutter detectado (v{fw.get('version','?')})"))

        # Banking security
        if banking and banking.get("available"):
            bank_risk = banking.get("risk_level", "")
            if bank_risk == "Critical":
                score += 20
                findings.append(("CRITICO", "App bancaria/alto valor con protecciones insuficientes"))
            elif bank_risk == "High":
                score += 12
                findings.append(("ALTO", "App alto valor con debilidades de seguridad"))
            for token in banking.get("token_extraction", []):
                if token.get("encrypted") is False:
                    score += 8
                    findings.append(("ALTO", f"Token {token.get('type','')} sin cifrado"))
            for at in banking.get("anti_tampering", []):
                if at.get("bypass_difficulty") in ("Easy", "Medium"):
                    score += 5
                    findings.append(("MEDIO", f"Anti-tamper {at.get('name','')} bypasseable ({at.get('bypass_difficulty','')})"))

        # Game anti-cheat
        if anticheat and anticheat.get("available"):
            for ac in anticheat.get("anticheat_systems", []):
                findings.append(("INFO", f"Anti-cheat detectado: {ac.get('name','')}"))
            for mp in anticheat.get("memory_protections", []):
                if mp.get("type") == "ptrace_anti_debug":
                    score += 3
                    findings.append(("MEDIO", "Protección ptrace anti-debug activa"))

        # --- Nuevos módulos forenses ---

        # Androwarn: comportamientos detectados
        if androwarn and androwarn.get("available"):
            aw_sev = androwarn.get("severity", "LIMPIO")
            aw_total = androwarn.get("total_behaviors", 0)
            if aw_sev == "CRITICO":
                score += 15
                findings.append(("CRITICO", f"Androwarn: {aw_total} comportamientos críticos (telefonía/A-V/ejecución)"))
            elif aw_sev == "ALTO":
                score += 8
                findings.append(("ALTO", f"Androwarn: {aw_total} comportamientos sospechosos"))
            elif aw_sev == "MEDIO":
                score += 4
                findings.append(("MEDIO", f"Androwarn: {aw_total} comportamientos detectados"))
            elif aw_sev == "BAJO":
                score += 1
                findings.append(("BAJO", f"Androwarn: {aw_total} comportamientos menores"))

        # Entropy/Obfuscation
        if entropy_obfuscation and entropy_obfuscation.get("available"):
            obf_score_val = entropy_obfuscation.get("obfuscation_score", 0)
            packed_count = len(entropy_obfuscation.get("packed_files", []))
            if obf_score_val >= 60:
                score += 10
                findings.append(("ALTO", f"Ofuscación fuerte detectada (score: {obf_score_val}/100, {packed_count} archivos packed)"))
            elif obf_score_val >= 30:
                score += 4
                findings.append(("MEDIO", f"Ofuscación moderada (ProGuard/R8, score: {obf_score_val}/100)"))
            if packed_count > 5:
                score += 5
                findings.append(("ALTO", f"{packed_count} archivos con entropía > 7.5 (posible packing)"))

        # Timeline: inconsistencias
        if timeline and timeline.get("available"):
            for inc in timeline.get("inconsistencies", []):
                inc_sev = inc.get("severity", "MEDIO")
                if inc_sev == "ALTO":
                    score += 5
                    findings.append(("ALTO", f"Timeline: {inc.get('description','')}"))
                elif inc_sev == "MEDIO":
                    score += 2
                    findings.append(("MEDIO", f"Timeline: {inc.get('description','')}"))

        # MITRE coverage as informational
        if mitre and mitre.get("available"):
            n_tech = mitre.get("total_techniques", 0)
            if n_tech >= 10:
                findings.append(("INFO", f"MITRE ATT&CK: {n_tech} técnicas mapeadas en {len(mitre.get('tactics', {}))} tácticas"))

        # --- Backdoor / C2 Detection ---
        if backdoor_c2 and backdoor_c2.get("available"):
            if backdoor_c2.get("has_backdoor_indicators"):
                score += 25
                findings.append(("CRITICO", f"Indicadores de backdoor/C2 detectados ({backdoor_c2.get('total_findings', 0)} hallazgos)"))
            if backdoor_c2.get("has_spyware_indicators"):
                score += 20
                findings.append(("CRITICO", f"Indicadores de spyware: keylogger/captura/grabación detectados"))
            if backdoor_c2.get("has_exfiltration"):
                score += 15
                findings.append(("CRITICO", f"Patrones de exfiltración de datos en código"))
            for cat_name, cat_items in backdoor_c2.get("by_category", {}).items():
                if cat_name in ("dga",):
                    score += 20
                    findings.append(("CRITICO", f"DGA (Domain Generation Algorithm) detectado: {len(cat_items)} indicadores"))

        # --- Endpoint Classification ---
        if endpoint_classification and endpoint_classification.get("available"):
            risk_sum = endpoint_classification.get("risk_summary", {})
            if risk_sum.get("c2_count", 0) > 0:
                score += min(risk_sum["c2_count"] * 10, 20)
                findings.append(("CRITICO", f"{risk_sum['c2_count']} endpoint(s) sospechoso(s) de C2"))
            if risk_sum.get("israeli_count", 0) > 0:
                score += min(risk_sum["israeli_count"] * 8, 20)
                findings.append(("ALTO", f"{risk_sum['israeli_count']} endpoint(s) con dominio israelí"))
            if risk_sum.get("surveillance_count", 0) > 0:
                score += min(risk_sum["surveillance_count"] * 12, 25)
                findings.append(("CRITICO", f"{risk_sum['surveillance_count']} endpoint(s) vinculados a empresas de vigilancia"))
            if risk_sum.get("tor_count", 0) > 0:
                score += min(risk_sum["tor_count"] * 10, 15)
                findings.append(("CRITICO", f"{risk_sum['tor_count']} endpoint(s) TOR/I2P detectados"))

        # --- Data Exfiltration Correlation ---
        if exfiltration and exfiltration.get("available"):
            ex_sum = exfiltration.get("summary", {})
            crit_chains = ex_sum.get("critical_chains", 0)
            high_chains = ex_sum.get("high_risk_chains", 0)
            if crit_chains > 0:
                score += min(crit_chains * 15, 25)
                data_types = ", ".join(ex_sum.get("data_types_at_risk", [])[:4])
                findings.append(("CRITICO", f"{crit_chains} cadena(s) de exfiltración confirmada(s): {data_types}"))
            if high_chains > 0:
                score += min(high_chains * 8, 15)
                findings.append(("ALTO", f"{high_chains} permiso(s) sensible(s) con acceso a red (riesgo exfiltración)"))

        # --- String Deobfuscation ---
        if string_deobfuscation and string_deobfuscation.get("available"):
            sd_crit = len(string_deobfuscation.get("by_severity", {}).get("CRITICO", []))
            sd_alto = len(string_deobfuscation.get("by_severity", {}).get("ALTO", []))
            if sd_crit > 0:
                score += min(sd_crit * 10, 20)
                findings.append(("CRITICO", f"Strings deobfuscadas: {sd_crit} críticas (exec/eval/shell/onion)"))
            if sd_alto > 0:
                score += min(sd_alto * 5, 15)
                findings.append(("ALTO", f"Strings deobfuscadas: {sd_alto} altas (URLs/credenciales/claves)"))

        # --- Signature Scheme ---
        if signature_scheme and signature_scheme.get("available"):
            sig_vulns = signature_scheme.get("vulnerabilities", [])
            for sv in sig_vulns:
                sev = sv.get("severity", "MEDIO")
                if sev == "CRITICO":
                    score += 15
                elif sev == "ALTO":
                    score += 8
                findings.append((sev, f"Firma: {sv.get('description', sv.get('id', ''))}"))
            if signature_scheme.get("janus_vulnerable"):
                score += 20
                findings.append(("CRITICO", "Vulnerable a Janus (CVE-2017-13156) - inyección de código sin invalidar firma"))

        # --- Deep Resources ---
        if deep_resources and deep_resources.get("available"):
            dr_crit = len(deep_resources.get("by_severity", {}).get("CRITICO", []))
            dr_alto = len(deep_resources.get("by_severity", {}).get("ALTO", []))
            dr_execs = len(deep_resources.get("embedded_executables", []))
            if dr_crit > 0:
                score += min(dr_crit * 12, 25)
                findings.append(("CRITICO", f"Recursos: {dr_crit} recursos críticos ({dr_execs} ejecutables embebidos)"))
            if dr_alto > 0:
                score += min(dr_alto * 5, 15)
                findings.append(("ALTO", f"Recursos: {dr_alto} recursos de alto riesgo (configs ocultas/payloads cifrados)"))

        # --- Accessibility / Overlay Abuse ---
        if accessibility_overlay and accessibility_overlay.get("available"):
            ao_risk = accessibility_overlay.get("risk_level", "BAJO")
            if ao_risk == "CRITICO":
                score += 25
                findings.append(("CRITICO", "Abuso de accesibilidad/overlay: patrón de troyano bancario detectado"))
            elif ao_risk == "ALTO":
                score += 15
                findings.append(("ALTO", f"Abuso de accesibilidad/overlay: {len(accessibility_overlay.get('code_findings', []))} patrones de riesgo"))
            elif ao_risk == "MEDIO":
                score += 5
                findings.append(("MEDIO", "Servicio de accesibilidad declarado (uso legítimo posible)"))

        # --- Intent/IPC Attack Surface ---
        if intent_ipc and intent_ipc.get("available"):
            ipc_score = intent_ipc.get("attack_surface_score", 0)
            ipc_crit = len(intent_ipc.get("by_severity", {}).get("CRITICO", []))
            ipc_unprotected = len(intent_ipc.get("unprotected_components", []))
            if ipc_crit > 0:
                score += min(ipc_crit * 8, 20)
                findings.append(("CRITICO", f"IPC: {ipc_crit} intents/schemes peligrosos"))
            if ipc_unprotected > 5:
                score += min(ipc_unprotected, 15)
                findings.append(("ALTO", f"IPC: {ipc_unprotected} componentes exportados sin protección"))
            pending = len(intent_ipc.get("pending_intent_risks", []))
            if pending > 0:
                score += min(pending * 5, 10)
                findings.append(("ALTO", f"IPC: {pending} PendingIntent con intent implícito (hijacking)"))

        # OWASP Mobile Top 10
        if owasp_mobile and owasp_mobile.get("available"):
            owasp_criticos = owasp_mobile.get("by_severity", {}).get("CRITICO", 0)
            owasp_altos = owasp_mobile.get("by_severity", {}).get("ALTO", 0)
            if owasp_criticos:
                score += min(owasp_criticos * 8, 20)
                findings.append(("CRITICO", f"OWASP: {owasp_criticos} categoría(s) con riesgo CRITICO"))
            if owasp_altos:
                score += min(owasp_altos * 5, 15)
                findings.append(("ALTO", f"OWASP: {owasp_altos} categoría(s) con riesgo ALTO"))

        # Clamp score AFTER all modules have contributed
        score = max(0, min(score, 100))

        if score >= 75: level, icon = "CRITICO", "\U0001f534"
        elif score >= 50: level, icon = "ALTO", "\U0001f7e0"
        elif score >= 25: level, icon = "MEDIO", "\U0001f7e1"
        else: level, icon = "BAJO", "\U0001f7e2"

        sev_order = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
        findings.sort(key=lambda x: sev_order.get(x[0], 5))

        return {"score": score, "level": level, "level_icon": icon, "findings": findings}

# ====================================================================
# MODULO 10: GENERACION DE REPORTES
# ====================================================================

class ReportGenerator:
    @staticmethod
    def generate_all(report_dir, target_file, data):
        md = ReportGenerator._gen_markdown(report_dir, target_file, data)
        js = ReportGenerator._gen_json(report_dir, target_file, data)
        ht = ReportGenerator._gen_html(report_dir, target_file, data)
        return md, js, ht

    @staticmethod
    def _gen_markdown(report_dir, target_file, data):
        path = os.path.join(report_dir, "REPORTE_FORENSE.md")
        app = os.path.basename(target_file)
        risk = data.get("risk", {})
        manifest = data.get("manifest", {})
        cert = data.get("certificate", {})
        network = data.get("network_security", {})
        secrets = data.get("secrets", {})
        smali = data.get("smali_analysis", {})
        structure = data.get("structure", {})
        trackers = data.get("trackers", {})
        file_info = data.get("file_info", {})
        hashes = data.get("hashes", {})

        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# REPORTE FORENSE - APKILIS v{VERSION}\n\n")
            f.write(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Archivo:** `{app}`\n\n")

            f.write(f"## VEREDICTO DE RIESGO\n\n")
            f.write(f"| Puntuacion | Nivel |\n|---|---|\n")
            f.write(f"| **{risk.get('score',0)}/100** | **{risk.get('level_icon','')} {risk.get('level','N/A')}** |\n\n")

            f.write(f"## 1. Cadena de Custodia\n\n")
            f.write(f"| Propiedad | Valor |\n|---|---|\n")
            f.write(f"| Nombre | `{app}` |\n")
            f.write(f"| Tamano | {file_info.get('size_human','N/A')} |\n")
            f.write(f"| MIME | `{file_info.get('mime_type','N/A')}` |\n")
            f.write(f"| MD5 | `{hashes.get('md5','N/A')}` |\n")
            f.write(f"| SHA1 | `{hashes.get('sha1','N/A')}` |\n")
            f.write(f"| SHA256 | `{hashes.get('sha256','N/A')}` |\n\n")

            f.write(f"## 2. Informacion del Paquete\n\n")
            f.write(f"| Propiedad | Valor |\n|---|---|\n")
            f.write(f"| Package | `{manifest.get('package','N/A')}` |\n")
            f.write(f"| Version | `{manifest.get('version_name','N/A')}` (code: {manifest.get('version_code','N/A')}) |\n")
            f.write(f"| minSdk | {manifest.get('min_sdk','N/A')} |\n")
            f.write(f"| targetSdk | {manifest.get('target_sdk','N/A')} |\n\n")

            f.write(f"## 3. Certificado de Firma\n\n")
            signer = cert.get("signer_info", {})
            f.write(f"| Propiedad | Valor |\n|---|---|\n")
            f.write(f"| Firmado | {'Si' if cert.get('is_signed') else 'No'} |\n")
            f.write(f"| V1 (JAR) | {'Si' if cert.get('v1_signed') else 'No'} |\n")
            f.write(f"| V2 (APK Sig) | {'Si' if cert.get('v2_signed') else 'No'} |\n")
            for k, v in signer.items():
                if k != "error":
                    f.write(f"| {k} | `{v}` |\n")
            f.write("\n")

            f.write(f"## 4. Flags de Seguridad\n\n")
            flags = manifest.get("flags", {})
            f.write(f"| Flag | Estado |\n|---|---|\n")
            f.write(f"| debuggable | {'PELIGRO' if flags.get('debuggable') else 'OK'} |\n")
            f.write(f"| allowBackup | {'RIESGO' if flags.get('allowBackup') else 'OK'} |\n")
            f.write(f"| usesCleartextTraffic | {'PELIGRO' if flags.get('usesCleartextTraffic') else 'OK'} |\n\n")

            f.write(f"## 5. Permisos ({len(manifest.get('permissions',[]))} total)\n\n")
            dangerous = manifest.get("dangerous_permission_details", [])
            if dangerous:
                f.write("### Permisos Peligrosos\n\n")
                f.write("| Permiso | Severidad | Descripcion |\n|---|---|---|\n")
                for pd in dangerous:
                    f.write(f"| `{pd['permission'].split('.')[-1]}` | {pd['severity']} | {pd['description']} |\n")
                f.write("\n")

            safe = [p for p in manifest.get("permissions",[]) if p not in [d["permission"] for d in dangerous]]
            if safe:
                f.write("### Otros Permisos\n\n")
                for p in safe:
                    f.write(f"- `{p}`\n")
                f.write("\n")

            exported = manifest.get("exported_components", [])
            if exported:
                f.write(f"## 6. Componentes Exportados ({len(exported)})\n\n")
                f.write("| Tipo | Nombre | Proteccion |\n|---|---|---|\n")
                for c in exported:
                    prot = c["permission"] if c.get("protected") else "Sin proteccion"
                    f.write(f"| {c['type']} | `{c['name']}` | {prot} |\n")
                f.write("\n")

            f.write(f"## 7. Seguridad de Red\n\n")
            if network.get("has_config"):
                f.write(f"- Config encontrada: Si\n")
                if network.get("cleartext_permitted") is not None:
                    f.write(f"- Cleartext HTTP: {'Permitido' if network['cleartext_permitted'] else 'Bloqueado'}\n")
                if network.get("trust_user_certs"):
                    f.write(f"- Certs de usuario: Confiados\n")
                if network.get("certificate_pinning"):
                    f.write(f"- Certificate Pinning: Configurado ({len(network['certificate_pinning'])} pins)\n")
            else:
                f.write("- Sin network_security_config.xml\n")
            f.write("\n")

            f.write(f"## 8. Trackers y SDKs ({trackers.get('total',0)})\n\n")
            if trackers.get("by_category"):
                for cat, items in trackers["by_category"].items():
                    f.write(f"### {cat}\n")
                    for t in items:
                        f.write(f"- **{t['name']}** (`{t['package']}`)\n")
                    f.write("\n")
            else:
                f.write("No se detectaron trackers.\n\n")

            f.write(f"## 9. Analisis de Codigo Smali\n\n")
            grouped = smali.get("grouped", {})
            if grouped:
                f.write("| Patron | Severidad | Descripcion | Ocurrencias |\n|---|---|---|---|\n")
                for name, info in sorted(grouped.items(),
                    key=lambda x: {"CRITICO":0,"ALTO":1,"MEDIO":2,"BAJO":3,"INFO":4}.get(x[1]["severity"],5)):
                    f.write(f"| {name} | {info['severity']} | {info['description']} | {info['count']} |\n")
                f.write("\n")

            f.write(f"## 10. Secretos y Datos Sensibles\n\n")
            if secrets:
                for stype, items in sorted(secrets.items()):
                    if not items: continue
                    show = min(len(items), 20)
                    f.write(f"### {stype} ({len(items)})\n\n")
                    for item in items[:show]:
                        di = item[:120] + "..." if len(item) > 120 else item
                        f.write(f"- `{di}`\n")
                    if len(items) > show:
                        f.write(f"- *...y {len(items)-show} mas*\n")
                    f.write("\n")

            f.write(f"## 11. Estructura del APK\n\n")
            f.write(f"- **Archivos:** {structure.get('total_files',0)}\n")
            f.write(f"- **Tamano:** {structure.get('total_size_human','N/A')}\n")
            f.write(f"- **DEX:** {len(structure.get('dex_files',[]))}\n")
            f.write(f"- **Libs nativas:** {len(structure.get('native_libs',[]))}\n")
            f.write(f"- **Arquitecturas:** {', '.join(structure.get('architectures',[])) or 'N/A'}\n\n")

            if structure.get("suspicious_assets"):
                f.write("### Assets Sospechosos\n\n")
                for sa in structure["suspicious_assets"]:
                    f.write(f"- `{sa['path']}` ({sa['size']})\n")
                f.write("\n")

            # Androguard
            ag = data.get("androguard", {})
            if ag.get("available"):
                f.write(f"## 12. Androguard - Analisis Profundo DEX\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| App Name | `{ag.get('app_name','N/A')}` |\n")
                f.write(f"| Main Activity | `{ag.get('main_activity','N/A')}` |\n")
                f.write(f"| Clases | {ag.get('class_count',0)} |\n")
                f.write(f"| Metodos | {ag.get('method_count',0)} |\n")
                f.write(f"| APIs peligrosas | {len(ag.get('dangerous_api_calls',[]))} |\n")
                f.write(f"| Strings interesantes | {len(ag.get('interesting_strings',[]))} |\n\n")

                api_calls = ag.get("dangerous_api_calls", [])
                if api_calls:
                    f.write("### APIs Peligrosas Detectadas\n\n")
                    f.write("| API | Categoria | Severidad | Descripcion |\n|---|---|---|---|\n")
                    for api in api_calls:
                        f.write(f"| `{api['api'][:60]}` | {api['category']} | {api['severity']} | {api['description']} |\n")
                    f.write("\n")

                interesting = ag.get("interesting_strings", [])[:30]
                if interesting:
                    f.write("### Strings Interesantes (top 30)\n\n")
                    for s in interesting:
                        ds = s[:120] + "..." if len(s) > 120 else s
                        f.write(f"- `{ds}`\n")
                    f.write("\n")

            # Quark-Engine
            quark = data.get("quark", {})
            if quark.get("available"):
                f.write(f"## 13. Quark-Engine - Heuristica de Malware\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Nivel de amenaza | **{quark.get('threat_level','N/A')}** |\n")
                f.write(f"| Clasificacion | {quark.get('classification',{}).get('label','N/A')} |\n")
                f.write(f"| Reglas escaneadas | {quark.get('rules_scanned',0)} |\n")
                f.write(f"| Reglas coincidentes | {len(quark.get('rules_matched',[]))} |\n\n")

                behaviors = quark.get("behaviors_detected", [])
                if behaviors:
                    f.write("### Comportamientos Detectados\n\n")
                    for b in behaviors:
                        f.write(f"#### {b['behavior']} ({b['count']} reglas)\n\n")
                        for r in b.get("rules", [])[:5]:
                            f.write(f"- **{r['crime']}** (score: {r['score']}, confianza: {r.get('confidence','N/A')})\n")
                        f.write("\n")

                matched = quark.get("rules_matched", [])[:20]
                if matched:
                    f.write("### Top Reglas Coincidentes\n\n")
                    f.write("| Regla | Crimen | Score | Confianza |\n|---|---|---|---|\n")
                    for r in matched:
                        f.write(f"| {r['rule']} | {r['crime'][:60]} | {r['score']} | {r.get('confidence','N/A')} |\n")
                    f.write("\n")

            # Enjarify
            enj = data.get("enjarify", {})
            if enj.get("available"):
                f.write(f"## 14. Enjarify - Conversion DEX a JAR\n\n")
                f.write(f"- **Metodo:** {enj.get('method','N/A')}\n")
                f.write(f"- **Clases Java:** {enj.get('class_count',0)}\n")
                f.write(f"- **JAR:** `{os.path.basename(enj.get('jar_path',''))}`\n\n")
                pkgs = enj.get("package_structure", [])[:20]
                if pkgs:
                    f.write("### Estructura de Paquetes (top 20)\n\n")
                    for p in pkgs:
                        f.write(f"- `{p}`\n")
                    f.write("\n")

            # YARA
            yara_d = data.get("yara", {})
            if yara_d.get("available"):
                f.write(f"## 15. YARA - Motor de Reglas y Firmas\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Reglas cargadas | {yara_d.get('rules_loaded',0)} |\n")
                f.write(f"| Archivos escaneados | {yara_d.get('files_scanned',0)} |\n")
                f.write(f"| Coincidencias | {len(yara_d.get('matches',[]))} |\n\n")
                ymatches = yara_d.get("matches", [])
                if ymatches:
                    f.write("### Detecciones\n\n")
                    f.write("| Regla | Categoria | Severidad | Descripcion |\n|---|---|---|---|\n")
                    for ym in ymatches:
                        f.write(f"| {ym['rule']} | {ym.get('category','')} | {ym.get('severity','')} | {ym.get('description','')} |\n")
                    f.write("\n")

            # APKiD
            apkid_d = data.get("apkid", {})
            if apkid_d.get("available"):
                f.write(f"## 16. APKiD - Packers, Ofuscadores, Protectores\n\n")
                for cat, key in [("Packers", "packers"), ("Ofuscadores", "obfuscators"),
                                 ("Protectores", "protectors"), ("Anti-Analisis", "anti_analysis"),
                                 ("Compiladores", "compilers")]:
                    items = apkid_d.get(key, [])
                    if items:
                        f.write(f"### {cat} ({len(items)})\n\n")
                        for item in items:
                            f.write(f"- {item.get('value', str(item))}\n")
                        f.write("\n")

            # LIEF
            lief_d = data.get("lief", {})
            if lief_d.get("available"):
                f.write(f"## 17. LIEF - Analisis de Librerias Nativas ELF\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Total libs .so | {lief_d.get('total_libs',0)} |\n")
                f.write(f"| Imports peligrosos | {len(lief_d.get('dangerous_imports_found',[]))} |\n")
                f.write(f"| Libs sospechosas | {len(lief_d.get('suspicious_libs',[]))} |\n")
                f.write(f"| Simbolos de debug | {'Si' if lief_d.get('has_debug_symbols') else 'No'} |\n\n")

                danger_imps = lief_d.get("dangerous_imports_found", [])
                if danger_imps:
                    f.write("### Imports Peligrosos\n\n")
                    f.write("| Funcion | Libreria | Severidad | Descripcion |\n|---|---|---|---|\n")
                    for di in danger_imps[:30]:
                        f.write(f"| `{di['function']}` | `{os.path.basename(di.get('library',''))}` | {di['severity']} | {di['description']} |\n")
                    f.write("\n")

                sus_libs = lief_d.get("suspicious_libs", [])
                if sus_libs:
                    f.write("### Librerias Sospechosas\n\n")
                    for sl in sus_libs:
                        f.write(f"- `{sl['path']}` - {sl['reason']}\n")
                    f.write("\n")

                for lib in lief_d.get("libraries", [])[:10]:
                    hes = lib.get("high_entropy_sections", [])
                    if hes:
                        f.write(f"- **{lib['name']}**: secciones alta entropia: {', '.join(s['name'] for s in hes)}\n")
                if any(lib.get("high_entropy_sections") for lib in lief_d.get("libraries", [])):
                    f.write("\n")

            # Endpoints
            ep_d = data.get("endpoints", {})
            if ep_d.get("available"):
                f.write(f"## 18. Endpoints - URLs, APIs y Recursos Cloud\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Total hallazgos | {ep_d.get('total_endpoints',0)} |\n")
                f.write(f"| Dominios unicos | {len(ep_d.get('unique_domains',[]))} |\n")
                for cat, items in ep_d.get("endpoints_by_type", {}).items():
                    if items:
                        f.write(f"| {cat} | {len(items)} |\n")
                f.write("\n")

                for cat in ("internal_ips", "cloud_resources", "auth_endpoints", "interesting_params",
                            "api_endpoints", "websocket_graphql", "deep_links"):
                    items = ep_d.get("endpoints_by_type", {}).get(cat, [])
                    if items:
                        f.write(f"### {cat.replace('_',' ').title()}\n\n")
                        f.write("| URL/Recurso | Archivo | Severidad |\n|---|---|---|\n")
                        for it in items[:30]:
                            val = it.get("url") or it.get("path") or it.get("ip") or it.get("uri") or it.get("domain", "")
                            f.write(f"| `{val}` | `{it.get('file','')}` | {it.get('severity','')} |\n")
                        f.write("\n")

            # Inyeccion
            inj_d = data.get("injection", {})
            if inj_d.get("available"):
                f.write(f"## 19. Inyeccion - Vulnerabilidades Detectadas\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Total vulnerabilidades | {inj_d.get('total_vulnerabilities',0)} |\n")
                for cat, items in inj_d.get("vulnerabilities_by_type", {}).items():
                    if items:
                        f.write(f"| {cat} | {len(items)} |\n")
                f.write(f"| Componentes exportados vulnerables | {len(inj_d.get('exported_attack_surface',[]))} |\n\n")

                for sev in ("CRITICO", "ALTO", "MEDIO"):
                    items = inj_d.get("by_severity", {}).get(sev, [])
                    if items:
                        f.write(f"### Severidad {sev}\n\n")
                        f.write("| Tipo | Descripcion | Archivo |\n|---|---|---|\n")
                        for it in items[:30]:
                            f.write(f"| {it.get('type','')} | {it.get('description','')} | `{it.get('file','')}` |\n")
                        f.write("\n")

                eas = inj_d.get("exported_attack_surface", [])
                if eas:
                    f.write("### Superficie de Ataque Exportada\n\n")
                    f.write("| Componente | Tipo Vuln | Severidad |\n|---|---|---|\n")
                    for e in eas:
                        f.write(f"| `{e.get('component','')}` | {e.get('type','')} | {e.get('severity','')} |\n")
                    f.write("\n")

            # Certificado profundo
            cc_d = data.get("crypto_cert", {})
            if cc_d.get("available"):
                f.write(f"## 20. Certificado X.509 - Analisis Profundo\n\n")
                for cert_info in cc_d.get("certificates", []):
                    subject = cert_info.get("subject", {})
                    issuer = cert_info.get("issuer", {})
                    f.write(f"### Certificado: {cert_info.get('file','')}\n\n")
                    f.write(f"| Propiedad | Valor |\n|---|---|\n")
                    f.write(f"| Subject CN | `{subject.get('commonName','N/A')}` |\n")
                    f.write(f"| Subject O | `{subject.get('organizationName','N/A')}` |\n")
                    f.write(f"| Issuer CN | `{issuer.get('commonName','N/A')}` |\n")
                    f.write(f"| Serial | `{cert_info.get('serial_number','N/A')}` |\n")
                    f.write(f"| Algoritmo | `{cert_info.get('signature_algorithm','N/A')}` |\n")
                    f.write(f"| Clave publica | {cert_info.get('public_key_type','')} {cert_info.get('public_key_size','')} bits |\n")
                    f.write(f"| Self-signed | {'Si' if cert_info.get('is_self_signed') else 'No'} |\n")
                    f.write(f"| Expirado | {'SI' if cert_info.get('is_expired') else 'No'} |\n")
                    f.write(f"| Validez | {cert_info.get('validity_years','')} anos |\n")
                    f.write(f"| SHA1 | `{cert_info.get('sha1_fingerprint','N/A')}` |\n")
                    f.write(f"| SHA256 | `{cert_info.get('sha256_fingerprint','N/A')}` |\n\n")
                anomalies = cc_d.get("cert_anomalies", [])
                if anomalies:
                    f.write("### Anomalias Detectadas\n\n")
                    for a in anomalies:
                        f.write(f"- ⚠ {a}\n")
                    f.write("\n")

            # Dynamic Analysis section
            dynamic = data.get("dynamic_analysis", {})
            if dynamic.get("available"):
                f.write(f"## 21. Kit de Análisis Dinámico\n\n")
                frida_scripts = dynamic.get("frida_scripts", {})
                if frida_scripts:
                    f.write("### Scripts Frida Generados\n\n")
                    f.write("| Script | Descripción |\n|---|---|\n")
                    script_descs = {
                        "ssl_pinning_bypass": "Bypass SSL/TLS certificate pinning",
                        "root_detection_bypass": "Bypass root/Magisk detection",
                        "anti_debug_bypass": "Bypass anti-debugging checks",
                        "crypto_hooks": "Hook crypto operations (AES/RSA/Hash)",
                        "network_monitor": "Monitor all HTTP/HTTPS traffic",
                        "method_tracer": "Trace target class methods",
                        "intent_monitor": "Monitor Intent broadcasts & activities",
                        "emulator_detection_bypass": "Bypass emulator detection",
                    }
                    for name, path_s in frida_scripts.items():
                        desc = script_descs.get(name, name)
                        f.write(f"| `{os.path.basename(path_s)}` | {desc} |\n")
                    f.write("\n")

                adb_cmds = dynamic.get("adb_commands", [])
                if adb_cmds:
                    f.write("### Comandos ADB\n\n")
                    for cat in adb_cmds:
                        f.write(f"**{cat.get('category','')}**\n```bash\n")
                        for cmd in cat.get("commands", []):
                            f.write(f"{cmd}\n")
                        f.write("```\n\n")

                drozer_cmds = dynamic.get("drozer_commands", [])
                if drozer_cmds:
                    f.write("### Comandos Drozer\n\n")
                    for cat in drozer_cmds:
                        f.write(f"**{cat.get('category','')}**\n```bash\n")
                        for cmd in cat.get("commands", []):
                            f.write(f"{cmd}\n")
                        f.write("```\n\n")

                obj_cmds = dynamic.get("objection_commands", [])
                if obj_cmds:
                    f.write("### Comandos Objection\n\n")
                    for cat in obj_cmds:
                        f.write(f"**{cat.get('category','')}**\n```bash\n")
                        for cmd in cat.get("commands", []):
                            f.write(f"{cmd}\n")
                        f.write("```\n\n")

                mem_cmds = dynamic.get("memory_dump_commands", [])
                if mem_cmds:
                    f.write("### Memory Dump Commands\n\n```bash\n")
                    for cat in mem_cmds:
                        f.write(f"# {cat.get('category','')}\n")
                        for cmd in cat.get("commands", []):
                            f.write(f"{cmd}\n")
                    f.write("```\n\n")

                hooks = dynamic.get("runtime_hooks", [])
                if hooks:
                    f.write("### Runtime Hooks Recomendados\n\n")
                    for h in hooks[:10]:
                        f.write(f"- `{h}`\n")
                    f.write("\n")

            # Forensic DB section
            fdb = data.get("forensic_db", {})
            if fdb.get("available"):
                f.write("## 22. Análisis Forense - Bases de Datos y Keystore\n\n")
                for db in fdb.get("databases", []):
                    ev = db.get('evidence', {})
                    ev_str = ev.get('string_found', str(ev)) if isinstance(ev, dict) else str(ev)
                    enc = db.get('encryption_status', 'unknown')
                    risk = db.get('risk_level', 'unknown')
                    f.write(f"- **{db.get('type','')}**: {ev_str[:120]} "
                            f"(Cifrado: {enc}, Riesgo: {risk})\n")
                if fdb.get("keystore_usage"):
                    f.write("\n### Android Keystore\n\n")
                    for ks in fdb["keystore_usage"]:
                        f.write(f"- {ks.get('provider','')}: {ks.get('evidence','')[:100]}\n")
                if fdb.get("cert_pinning_analysis"):
                    f.write("\n### Certificate Pinning\n\n")
                    f.write("| Tipo | Bypass | Evidencia |\n|---|---|---|\n")
                    for pin in fdb["cert_pinning_analysis"]:
                        f.write(f"| {pin.get('type','')} | {pin.get('bypass_difficulty','')} | {pin.get('evidence','')[:60]} |\n")
                f.write("\n")

            # Framework section
            fw = data.get("framework", {})
            if fw.get("available") and fw.get("detected_frameworks"):
                f.write("## 23. Frameworks Detectados\n\n")
                for fwd in fw["detected_frameworks"]:
                    f.write(f"### {fwd.get('name','')} (Confianza: {fwd.get('confidence','')})\n\n")
                    if fwd.get("version"):
                        f.write(f"- Versión: {fwd['version']}\n")
                    for ev_k, ev_v in fwd.get("evidence", {}).items():
                        f.write(f"- {ev_k}: `{ev_v}`\n")
                    if fwd.get("analysis_commands"):
                        f.write("\n**Comandos de análisis:**\n```bash\n")
                        for cmd in fwd["analysis_commands"][:10]:
                            f.write(f"{cmd}\n")
                        f.write("```\n\n")

            # Banking section
            bank = data.get("banking", {})
            if bank.get("available"):
                f.write("## 24. Seguridad Bancaria / Alto Valor\n\n")
                f.write(f"**Nivel de Riesgo:** {bank.get('risk_level','N/A')}\n\n")
                for cat_name, cat_key in [("Secure Element", "secure_element"),
                    ("Biometría", "biometric_analysis"), ("Hardware Keystore", "hardware_keystore"),
                    ("Tokens", "token_extraction"), ("Anti-Tampering", "anti_tampering"),
                    ("Patrones Bancarios", "banking_patterns")]:
                    items = bank.get(cat_key, [])
                    if items:
                        f.write(f"### {cat_name}\n\n")
                        for item in items[:8]:
                            if isinstance(item, dict):
                                f.write(f"- {item.get('type', item.get('name', ''))}: "
                                        f"{item.get('evidence', item.get('description', ''))[:100]}\n")
                        f.write("\n")

            # Anti-cheat section
            ac = data.get("anticheat", {})
            if ac.get("available") and (ac.get("anticheat_systems") or ac.get("memory_protections")):
                f.write("## 25. Análisis Anti-Cheat de Juegos\n\n")
                if ac.get("anticheat_systems"):
                    f.write("### Sistemas Detectados\n\n")
                    f.write("| Sistema | Dificultad Bypass | Evidencia |\n|---|---|---|\n")
                    for sys_ac in ac["anticheat_systems"]:
                        f.write(f"| {sys_ac.get('name','')} | {sys_ac.get('bypass_difficulty','')} | "
                                f"{', '.join(sys_ac.get('evidence',[])[:3])} |\n")
                    f.write("\n")
                if ac.get("memory_protections"):
                    f.write("### Protecciones de Memoria\n\n")
                    for mp in ac["memory_protections"]:
                        f.write(f"- **{mp.get('type','')}**: {mp.get('description', mp.get('implementation',''))[:100]}\n")
                    f.write("\n")
                if ac.get("reverse_commands"):
                    f.write("### Comandos de Reverse Engineering\n\n")
                    for rc in ac["reverse_commands"]:
                        f.write(f"**{rc.get('engine','')}**\n```bash\n")
                        for cmd in rc.get("commands",[])[:8]:
                            f.write(f"{cmd}\n")
                        f.write("```\n\n")

            # Androwarn
            aw = data.get("androwarn", {})
            if aw.get("available"):
                f.write("## 26. Androwarn - Análisis de Comportamientos\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Severidad | **{aw.get('severity','N/A')}** |\n")
                f.write(f"| Total comportamientos | {aw.get('total_behaviors',0)} |\n")
                f.write(f"| Categorías | {len(aw.get('behaviors',{}))} |\n\n")
                for cat, bdata in aw.get("behaviors", {}).items():
                    f.write(f"### {cat.replace('_',' ').title()} ({bdata.get('count',0)})\n\n")
                    for detail in bdata.get("details", [])[:10]:
                        f.write(f"- {str(detail)[:150]}\n")
                    f.write("\n")

            # Fuzzy Hashing
            fh = data.get("fuzzy_hashes", {})
            if fh.get("available"):
                f.write("## 27. Fuzzy Hashing (ssdeep + TLSH)\n\n")
                apk_h = fh.get("apk_hashes", {})
                if apk_h.get("ssdeep"):
                    f.write(f"- **ssdeep (APK):** `{apk_h['ssdeep']}`\n")
                if apk_h.get("tlsh"):
                    f.write(f"- **TLSH (APK):** `{apk_h['tlsh']}`\n")
                f.write("\n")
                dex_h = fh.get("dex_hashes", [])
                if dex_h:
                    f.write("### Hashes por DEX\n\n")
                    f.write("| DEX | Tamaño | ssdeep | TLSH |\n|---|---|---|---|\n")
                    for dh in dex_h:
                        f.write(f"| {dh['file']} | {dh['size']} | `{dh.get('ssdeep','N/A')[:40]}...` | `{str(dh.get('tlsh','N/A'))[:40]}...` |\n")
                    f.write("\n")

            # Entropy + Obfuscation
            eo = data.get("entropy_obfuscation", {})
            if eo.get("available"):
                f.write("## 28. Entropía y Ofuscación\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Entropía media | {eo.get('overall_entropy',0):.4f} |\n")
                f.write(f"| Archivos packed (>7.5) | {len(eo.get('packed_files',[]))} |\n")
                f.write(f"| Score ofuscación | **{eo.get('obfuscation_score',0)}/100** |\n\n")
                obf_inds = eo.get("obfuscation_indicators", [])
                if obf_inds:
                    f.write("### Indicadores de Ofuscación\n\n")
                    for ind in obf_inds:
                        f.write(f"- ⚠ {ind}\n")
                    f.write("\n")
                dex_a = eo.get("dex_analysis", [])
                if dex_a:
                    f.write("### Análisis DEX\n\n")
                    f.write("| DEX | Entropía | Nombres cortos | Entropía IDs |\n|---|---|---|---|\n")
                    for da in dex_a:
                        f.write(f"| {da['file']} | {da['entropy']:.4f} | {da.get('short_names_ratio',0):.0%} | {da.get('identifier_entropy',0):.2f} |\n")
                    f.write("\n")

            # MITRE ATT&CK
            mitre_d = data.get("mitre_attack", {})
            if mitre_d.get("available") and mitre_d.get("techniques"):
                f.write("## 29. MITRE ATT&CK for Mobile\n\n")
                f.write(f"**Total técnicas mapeadas:** {mitre_d.get('total_techniques',0)}\n\n")
                for tactic, tids in sorted(mitre_d.get("tactics", {}).items()):
                    f.write(f"### {tactic} ({len(tids)})\n\n")
                    f.write("| Técnica | Nombre | Fuentes | Evidencia |\n|---|---|---|---|\n")
                    techs = mitre_d.get("techniques", {})
                    for tid in tids:
                        t = techs.get(tid, {})
                        sources = ", ".join(t.get("sources", []))
                        evidence = "; ".join(t.get("evidence", [])[:2])[:100]
                        f.write(f"| {tid} | {t.get('name','')} | {sources} | {evidence} |\n")
                    f.write("\n")

            # Forensic Timeline
            tl = data.get("forensic_timeline", {})
            if tl.get("available"):
                f.write("## 30. Línea de Tiempo Forense\n\n")
                tr = tl.get("time_range", {})
                f.write(f"- **Rango:** {tr.get('earliest','N/A')} — {tr.get('latest','N/A')}\n")
                f.write(f"- **Total eventos:** {tr.get('total_events',0)}\n")
                f.write(f"- **Inconsistencias:** {len(tl.get('inconsistencies',[]))}\n\n")
                incons = tl.get("inconsistencies", [])
                if incons:
                    f.write("### Inconsistencias Detectadas\n\n")
                    f.write("| Tipo | Severidad | Descripción |\n|---|---|---|\n")
                    for inc in incons:
                        f.write(f"| {inc.get('type','')} | {inc.get('severity','')} | {inc.get('description','')} |\n")
                    f.write("\n")
                events_list = tl.get("events", [])[:30]
                if events_list:
                    f.write("### Cronología (primeros 30 eventos)\n\n")
                    f.write("| Timestamp | Fuente | Evento |\n|---|---|---|\n")
                    for ev in events_list:
                        f.write(f"| {ev.get('timestamp','')} | {ev.get('source','')} | {ev.get('event','')[:80]} |\n")
                    f.write("\n")

            # String Deobfuscation
            sd = data.get("string_deobfuscation", {})
            if sd.get("available") and sd.get("total_decoded", 0) > 0:
                f.write("## 31. Deobfuscación de Strings\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Total decodificadas | {sd.get('total_decoded', 0)} |\n")
                f.write(f"| Interesantes | {len(sd.get('interesting_strings', []))} |\n")
                for enc, cnt in sd.get("by_encoding", {}).items():
                    if cnt > 0:
                        f.write(f"| {enc} | {cnt} |\n")
                f.write("\n")
                interesting = sd.get("interesting_strings", [])
                if interesting:
                    f.write("### Strings Interesantes Decodificadas\n\n")
                    f.write("| Severidad | Encoding | Decodificado | Archivo |\n|---|---|---|---|\n")
                    for s in interesting[:30]:
                        f.write(f"| {s['severity']} | {s['encoding']} | `{s['decoded'][:80]}` | `{s['file']}` |\n")
                    f.write("\n")

            # Signature Scheme
            sig = data.get("signature_scheme", {})
            if sig.get("available"):
                f.write("## 32. Esquemas de Firma APK\n\n")
                f.write("| Esquema | Estado |\n|---|---|\n")
                for k, v in sig.get("schemes", {}).items():
                    f.write(f"| {k} | {'✓ Presente' if v else '✗ Ausente'} |\n")
                f.write("\n")
                vulns = sig.get("vulnerabilities", [])
                if vulns:
                    f.write("### Vulnerabilidades de Firma\n\n")
                    f.write("| ID | Severidad | Descripción |\n|---|---|---|\n")
                    for v in vulns:
                        f.write(f"| {v.get('id','')} | {v.get('severity','')} | {v.get('description','')} |\n")
                    f.write("\n")

            # Deep Resources
            dr = data.get("deep_resources", {})
            if dr.get("available") and (dr.get("suspicious_resources") or dr.get("hidden_configs") or dr.get("embedded_databases")):
                f.write("## 33. Análisis Profundo de Recursos\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Recursos sospechosos | {len(dr.get('suspicious_resources', []))} |\n")
                f.write(f"| Configs ocultas | {len(dr.get('hidden_configs', []))} |\n")
                f.write(f"| DBs embebidas | {len(dr.get('embedded_databases', []))} |\n")
                f.write(f"| Ejecutables embebidos | {len(dr.get('embedded_executables', []))} |\n\n")
                sus = dr.get("suspicious_resources", [])
                if sus:
                    f.write("### Recursos Sospechosos\n\n")
                    f.write("| Ruta | Tipo | Tamaño | Severidad | Descripción |\n|---|---|---|---|---|\n")
                    for s in sus[:25]:
                        f.write(f"| `{s.get('path','')}` | {s.get('extension','')} | {s.get('size',0)} | {s.get('severity','')} | {s.get('description','')} |\n")
                    f.write("\n")
                hc = dr.get("hidden_configs", [])
                if hc:
                    f.write("### Configuraciones Ocultas\n\n")
                    for c in hc[:10]:
                        f.write(f"- **`{c.get('path','')}`** ({c.get('type','')}): claves sospechosas: {', '.join(c.get('suspicious_keys',[])[:5])}\n")
                    f.write("\n")
                dbs = dr.get("embedded_databases", [])
                if dbs:
                    f.write("### Bases de Datos Embebidas\n\n")
                    for db in dbs[:10]:
                        f.write(f"- **`{db.get('path','')}`** ({db.get('size',0)} bytes): tablas: {', '.join(db.get('tables',[])[:8])}\n")
                    f.write("\n")

            # Accessibility / Overlay
            ao = data.get("accessibility_overlay", {})
            if ao.get("available") and (ao.get("has_accessibility_service") or ao.get("has_overlay_permission")):
                f.write("## 34. Accesibilidad y Overlay\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| AccessibilityService | {'SÍ' if ao.get('has_accessibility_service') else 'NO'} |\n")
                f.write(f"| Overlay (SYSTEM_ALERT_WINDOW) | {'SÍ' if ao.get('has_overlay_permission') else 'NO'} |\n")
                f.write(f"| Nivel de riesgo | {ao.get('risk_level', 'N/A')} |\n")
                f.write(f"| Hallazgos en código | {len(ao.get('code_findings', []))} |\n\n")
                indicators = ao.get("risk_indicators", [])
                if indicators:
                    f.write("### Indicadores de Riesgo\n\n")
                    for ind in indicators:
                        f.write(f"- **[{ind['severity']}]** {ind['indicator']}: {ind.get('detail','')}\n")
                    f.write("\n")
                findings_ao = ao.get("code_findings", [])
                if findings_ao:
                    f.write("### Patrones de Abuso en Código\n\n")
                    f.write("| Patrón | Severidad | Descripción | Archivo | # |\n|---|---|---|---|---|\n")
                    for fa in findings_ao[:20]:
                        f.write(f"| {fa['pattern']} | {fa['severity']} | {fa['description']} | `{os.path.basename(fa.get('file',''))}` | {fa.get('count',0)} |\n")
                    f.write("\n")

            # Intent/IPC Attack Surface
            ipc = data.get("intent_ipc", {})
            if ipc.get("available"):
                f.write("## 35. Superficie de Ataque Intent/IPC\n\n")
                f.write(f"| Metrica | Valor |\n|---|---|\n")
                f.write(f"| Componentes sin proteger | {len(ipc.get('unprotected_components', []))} |\n")
                f.write(f"| Deep links | {len(ipc.get('deep_links', []))} |\n")
                f.write(f"| Intents peligrosos | {len(ipc.get('dangerous_intents', []))} |\n")
                f.write(f"| PendingIntent riesgosos | {len(ipc.get('pending_intent_risks', []))} |\n")
                f.write(f"| Score superficie de ataque | {ipc.get('attack_surface_score', 0)}/100 |\n\n")
                dlinks = ipc.get("deep_links", [])
                if dlinks:
                    f.write("### Deep Links\n\n")
                    f.write("| Actividad | URI |\n|---|---|\n")
                    for dl in dlinks[:20]:
                        f.write(f"| `{dl.get('activity','')}` | `{dl.get('full_uri', dl.get('scheme',''))}` |\n")
                    f.write("\n")
                unp = ipc.get("unprotected_components", [])
                if unp:
                    f.write("### Componentes Exportados Sin Protección\n\n")
                    f.write("| Nombre | Tipo |\n|---|---|\n")
                    for u in unp[:20]:
                        f.write(f"| `{u.get('name','')}` | {u.get('type','')} |\n")
                    f.write("\n")
                di = ipc.get("dangerous_intents", [])
                if di:
                    f.write("### Intents Peligrosos\n\n")
                    f.write("| Severidad | Componente/Scheme | Descripción |\n|---|---|---|\n")
                    for d in di[:15]:
                        comp = d.get("component", d.get("activity", d.get("scheme", "")))
                        f.write(f"| {d['severity']} | `{comp}` | {d['description']} |\n")
                    f.write("\n")

            # OWASP Mobile Top 10 2024
            owasp = data.get("owasp_mobile", {})
            if owasp.get("available"):
                f.write(f"## 36. OWASP Mobile Top 10 2024\n\n")
                f.write(f"**Puntuación global:** {owasp.get('overall_score', 0)}/100 | ")
                f.write(f"**Severidad:** {owasp.get('overall_severity', 'N/A')} | ")
                f.write(f"**Total hallazgos:** {owasp.get('total_findings', 0)}\n\n")
                bs = owasp.get("by_severity", {})
                f.write(f"CRITICO: {bs.get('CRITICO',0)} | ALTO: {bs.get('ALTO',0)} | MEDIO: {bs.get('MEDIO',0)} | BAJO: {bs.get('BAJO',0)}\n\n")
                f.write("| ID | Categoría | Severidad | Score | Hallazgos |\n|---|---|---|---|---|\n")
                for cat in owasp.get("categories", []):
                    f.write(f"| {cat['id']} | {cat['name']} | {cat['severity']} | {cat['score']}/100 | {len(cat.get('findings',[]))} |\n")
                f.write("\n")
                for cat in owasp.get("categories", []):
                    if cat.get("findings"):
                        f.write(f"### {cat['id']} - {cat['name']}\n\n")
                        f.write("| Severidad | Descripción | Evidencia |\n|---|---|---|\n")
                        for finding in cat["findings"][:15]:
                            f.write(f"| {finding.get('severity','')} | {finding.get('description','')} | `{finding.get('evidence','')[:80]}` |\n")
                        f.write(f"\n**Recomendación:** {cat.get('recommendation','')}\n\n")

            f.write(f"## 37. Resumen de Hallazgos\n\n")
            f.write("| # | Severidad | Hallazgo |\n|---|---|---|\n")
            for i, (sev, desc) in enumerate(risk.get("findings",[]), 1):
                f.write(f"| {i} | {sev} | {desc} |\n")
            f.write("\n---\n")
            f.write(f"*APKILIS v{VERSION} - Analisis forense 100% local/offline*\n")

        return path

    @staticmethod
    def _gen_json(report_dir, target_file, data):
        path = os.path.join(report_dir, "resultado.json")
        def ser(obj):
            if isinstance(obj, set): return sorted(list(obj))
            if isinstance(obj, datetime): return obj.isoformat()
            return obj

        export = {
            "meta": {"tool": f"APKILIS v{VERSION}", "date": datetime.now().isoformat(),
                     "file": os.path.basename(target_file)},
            "file_info": data.get("file_info", {}),
            "hashes": data.get("hashes", {}),
            "risk": data.get("risk", {}),
            "manifest": data.get("manifest", {}),
            "certificate": data.get("certificate", {}),
            "network_security": data.get("network_security", {}),
            "trackers": data.get("trackers", {}),
            "smali_analysis": {"grouped": data.get("smali_analysis",{}).get("grouped",{}),
                               "files_scanned": data.get("smali_analysis",{}).get("files_scanned",0)},
            "secrets": data.get("secrets", {}),
            "structure": data.get("structure", {}),
            "androguard": data.get("androguard", {}),
            "quark": data.get("quark", {}),
            "enjarify": data.get("enjarify", {}),
            "yara": data.get("yara", {}),
            "apkid": data.get("apkid", {}),
            "lief": data.get("lief", {}),
            "endpoints": data.get("endpoints", {}),
            "injection": data.get("injection", {}),
            "crypto_cert": data.get("crypto_cert", {}),
            "dynamic_analysis": {
                "available": data.get("dynamic_analysis", {}).get("available", False),
                "summary": data.get("dynamic_analysis", {}).get("summary", ""),
                "scripts_generated": [os.path.basename(s) for s in
                    data.get("dynamic_analysis", {}).get("frida_scripts", {}).values()],
                "adb_commands_count": sum(len(c.get("commands",[])) for c in
                    data.get("dynamic_analysis", {}).get("adb_commands", [])),
                "drozer_commands_count": sum(len(c.get("commands",[])) for c in
                    data.get("dynamic_analysis", {}).get("drozer_commands", [])),
                "runtime_hooks_count": len(data.get("dynamic_analysis", {}).get("runtime_hooks", [])),
            },
            "forensic_db": {
                "available": data.get("forensic_db", {}).get("available", False),
                "databases_count": len(data.get("forensic_db", {}).get("databases", [])),
                "keystore_refs": len(data.get("forensic_db", {}).get("keystore_usage", [])),
                "cert_pinning_count": len(data.get("forensic_db", {}).get("cert_pinning_analysis", [])),
                "summary": data.get("forensic_db", {}).get("summary", ""),
            },
            "framework": {
                "available": data.get("framework", {}).get("available", False),
                "primary": data.get("framework", {}).get("primary_framework"),
                "detected": [{"name": f.get("name"), "confidence": f.get("confidence"),
                              "version": f.get("version")}
                             for f in data.get("framework", {}).get("detected_frameworks", [])],
                "summary": data.get("framework", {}).get("summary", ""),
            },
            "banking": {
                "available": data.get("banking", {}).get("available", False),
                "risk_level": data.get("banking", {}).get("risk_level", ""),
                "secure_element_count": len(data.get("banking", {}).get("secure_element", [])),
                "biometric_count": len(data.get("banking", {}).get("biometric_analysis", [])),
                "token_count": len(data.get("banking", {}).get("token_extraction", [])),
                "anti_tampering_count": len(data.get("banking", {}).get("anti_tampering", [])),
                "summary": data.get("banking", {}).get("summary", ""),
            },
            "anticheat": {
                "available": data.get("anticheat", {}).get("available", False),
                "systems": [s.get("name") for s in data.get("anticheat", {}).get("anticheat_systems", [])],
                "memory_protections_count": len(data.get("anticheat", {}).get("memory_protections", [])),
                "risk_level": data.get("anticheat", {}).get("risk_level", ""),
                "summary": data.get("anticheat", {}).get("summary", ""),
            },
            "string_deobfuscation": {
                "available": data.get("string_deobfuscation", {}).get("available", False),
                "total_decoded": data.get("string_deobfuscation", {}).get("total_decoded", 0),
                "interesting_strings": data.get("string_deobfuscation", {}).get("interesting_strings", [])[:50],
                "by_encoding": data.get("string_deobfuscation", {}).get("by_encoding", {}),
                "summary": data.get("string_deobfuscation", {}).get("summary", ""),
            },
            "signature_scheme": {
                "available": data.get("signature_scheme", {}).get("available", False),
                "schemes": data.get("signature_scheme", {}).get("schemes", {}),
                "vulnerabilities": data.get("signature_scheme", {}).get("vulnerabilities", []),
                "janus_vulnerable": data.get("signature_scheme", {}).get("janus_vulnerable", False),
                "summary": data.get("signature_scheme", {}).get("summary", ""),
            },
            "deep_resources": {
                "available": data.get("deep_resources", {}).get("available", False),
                "suspicious_resources": data.get("deep_resources", {}).get("suspicious_resources", [])[:30],
                "hidden_configs": data.get("deep_resources", {}).get("hidden_configs", [])[:20],
                "embedded_databases": [{"path": d.get("path"), "tables": d.get("tables", []), "size": d.get("size")}
                                       for d in data.get("deep_resources", {}).get("embedded_databases", [])[:10]],
                "embedded_executables": data.get("deep_resources", {}).get("embedded_executables", [])[:20],
                "summary": data.get("deep_resources", {}).get("summary", ""),
            },
            "accessibility_overlay": {
                "available": data.get("accessibility_overlay", {}).get("available", False),
                "has_accessibility_service": data.get("accessibility_overlay", {}).get("has_accessibility_service", False),
                "has_overlay_permission": data.get("accessibility_overlay", {}).get("has_overlay_permission", False),
                "risk_level": data.get("accessibility_overlay", {}).get("risk_level", ""),
                "code_findings_count": len(data.get("accessibility_overlay", {}).get("code_findings", [])),
                "risk_indicators": data.get("accessibility_overlay", {}).get("risk_indicators", []),
                "summary": data.get("accessibility_overlay", {}).get("summary", ""),
            },
            "intent_ipc": {
                "available": data.get("intent_ipc", {}).get("available", False),
                "unprotected_count": len(data.get("intent_ipc", {}).get("unprotected_components", [])),
                "deep_links": data.get("intent_ipc", {}).get("deep_links", [])[:20],
                "dangerous_intents": data.get("intent_ipc", {}).get("dangerous_intents", [])[:20],
                "pending_intent_risks": len(data.get("intent_ipc", {}).get("pending_intent_risks", [])),
                "attack_surface_score": data.get("intent_ipc", {}).get("attack_surface_score", 0),
                "summary": data.get("intent_ipc", {}).get("summary", ""),
            },
            "owasp_mobile": data.get("owasp_mobile", {}),
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(export, f, indent=2, ensure_ascii=False, default=ser)
        return path

    @staticmethod
    def _gen_html(report_dir, target_file, data):
        if not HAS_JINJA:
            return None

        path = os.path.join(report_dir, "REPORTE_FORENSE.html")
        app = os.path.basename(target_file)
        risk = data.get("risk", {})
        manifest = data.get("manifest", {})
        cert = data.get("certificate", {})
        hashes_d = data.get("hashes", {})
        file_info = data.get("file_info", {})
        network = data.get("network_security", {})
        secrets = data.get("secrets", {})
        smali = data.get("smali_analysis", {})
        structure = data.get("structure", {})
        trackers = data.get("trackers", {})
        total_secrets = sum(len(v) for v in secrets.values()) if isinstance(secrets, dict) else 0

        tpl = Template("""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>APKILIS - {{ app }}</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--text2:#8b949e;
--red:#f85149;--orange:#d29922;--green:#3fb950;--blue:#58a6ff;--purple:#bc8cff}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{color:var(--blue);font-size:1.8em;margin-bottom:5px}
h2{color:var(--purple);font-size:1.3em;margin:25px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--border)}
h3{color:var(--text);font-size:1.05em;margin:15px 0 8px}
.header{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:25px;margin-bottom:20px;text-align:center}
.risk-badge{display:inline-block;font-size:2.5em;font-weight:bold;padding:15px 40px;border-radius:12px;margin:15px 0}
.risk-CRITICO{background:#f8514922;color:var(--red);border:2px solid var(--red)}
.risk-ALTO{background:#d2992222;color:var(--orange);border:2px solid var(--orange)}
.risk-MEDIO{background:#d2992211;color:#e3b341;border:2px solid #e3b341}
.risk-BAJO{background:#3fb95022;color:var(--green);border:2px solid var(--green)}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:15px}
table{width:100%;border-collapse:collapse;margin:10px 0}
th{background:#21262d;color:var(--blue);text-align:left;padding:10px 12px;font-size:.85em;text-transform:uppercase}
td{padding:8px 12px;border-bottom:1px solid var(--border);font-size:.9em}
tr:hover td{background:#1c2128}
code{background:#1c2128;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:.85em;color:var(--blue)}
.sev-CRITICO{color:var(--red);font-weight:bold}.sev-ALTO{color:var(--orange);font-weight:bold}
.sev-MEDIO{color:#e3b341}.sev-BAJO{color:var(--green)}.sev-INFO{color:var(--text2)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px}
.stat{text-align:center;padding:15px}.stat-num{font-size:2em;font-weight:bold;color:var(--blue)}.stat-label{color:var(--text2);font-size:.85em}
.meta{color:var(--text2);font-size:.85em}
ul{list-style:none;padding:0}ul li{padding:3px 0}ul li:before{content:">";color:var(--blue);margin-right:8px}
footer{text-align:center;color:var(--text2);margin-top:40px;padding:20px;border-top:1px solid var(--border);font-size:.85em}
</style></head><body><div class="container">
<div class="header"><h1>APKILIS - Reporte Forense</h1>
<p class="meta">{{ date }} | {{ app }} | 100% Offline</p>
<div class="risk-badge risk-{{ risk_level }}">{{ risk_icon }} {{ risk_score }}/100 - {{ risk_level }}</div></div>
<div class="grid">
<div class="card stat"><div class="stat-num">{{ perms_count }}</div><div class="stat-label">Permisos</div></div>
<div class="card stat"><div class="stat-num">{{ exported_count }}</div><div class="stat-label">Exportados</div></div>
<div class="card stat"><div class="stat-num">{{ trackers_count }}</div><div class="stat-label">Trackers</div></div>
<div class="card stat"><div class="stat-num">{{ total_secrets }}</div><div class="stat-label">Secretos</div></div>
</div>
<div class="card"><h2>Cadena de Custodia</h2><table>
<tr><td><strong>Archivo</strong></td><td><code>{{ app }}</code></td></tr>
<tr><td><strong>Tamano</strong></td><td>{{ size }}</td></tr>
<tr><td><strong>MD5</strong></td><td><code>{{ md5 }}</code></td></tr>
<tr><td><strong>SHA1</strong></td><td><code>{{ sha1 }}</code></td></tr>
<tr><td><strong>SHA256</strong></td><td><code>{{ sha256 }}</code></td></tr>
</table></div>
<div class="card"><h2>Paquete</h2><table>
<tr><td><strong>Package</strong></td><td><code>{{ package }}</code></td></tr>
<tr><td><strong>Version</strong></td><td>{{ version_name }} ({{ version_code }})</td></tr>
<tr><td><strong>minSdk</strong></td><td>{{ min_sdk }}</td></tr>
<tr><td><strong>targetSdk</strong></td><td>{{ target_sdk }}</td></tr>
</table></div>
<div class="card"><h2>Certificado</h2><table>
<tr><td><strong>Firmado</strong></td><td>{{ 'Si' if is_signed else 'No' }}</td></tr>
<tr><td><strong>V1</strong></td><td>{{ 'Si' if v1 else 'No' }}</td></tr>
<tr><td><strong>V2</strong></td><td>{{ 'Si' if v2 else 'No' }}</td></tr>
{% for k,v in signer.items() %}<tr><td><strong>{{ k }}</strong></td><td><code>{{ v }}</code></td></tr>{% endfor %}
</table></div>
<div class="card"><h2>Flags de Seguridad</h2><table><tr><th>Flag</th><th>Estado</th></tr>
<tr><td>debuggable</td><td class="{{ 'sev-CRITICO' if debuggable else 'sev-BAJO' }}">{{ 'PELIGRO' if debuggable else 'OK' }}</td></tr>
<tr><td>allowBackup</td><td class="{{ 'sev-ALTO' if allow_backup else 'sev-BAJO' }}">{{ 'RIESGO' if allow_backup else 'OK' }}</td></tr>
<tr><td>usesCleartextTraffic</td><td class="{{ 'sev-CRITICO' if cleartext else 'sev-BAJO' }}">{{ 'PELIGRO' if cleartext else 'OK' }}</td></tr>
</table></div>
{% if dangerous_perms %}<div class="card"><h2>Permisos Peligrosos</h2><table><tr><th>Permiso</th><th>Severidad</th><th>Descripcion</th></tr>
{% for p in dangerous_perms %}<tr><td><code>{{ p.permission.split('.')[-1] }}</code></td><td class="sev-{{ p.severity }}">{{ p.severity }}</td><td>{{ p.description }}</td></tr>{% endfor %}
</table></div>{% endif %}
{% if exported %}<div class="card"><h2>Componentes Exportados ({{ exported|length }})</h2><table><tr><th>Tipo</th><th>Nombre</th><th>Proteccion</th></tr>
{% for c in exported %}<tr><td>{{ c.type }}</td><td><code>{{ c.name }}</code></td><td>{{ c.permission if c.protected else 'Sin proteccion' }}</td></tr>{% endfor %}
</table></div>{% endif %}
{% if tracker_cats %}<div class="card"><h2>Trackers ({{ trackers_count }})</h2>
{% for cat, items in tracker_cats.items() %}<h3>{{ cat }}</h3><ul>{% for t in items %}<li><strong>{{ t.name }}</strong> <code>{{ t.package }}</code></li>{% endfor %}</ul>{% endfor %}
</div>{% endif %}
{% if smali_grouped %}<div class="card"><h2>Analisis de Codigo</h2><table><tr><th>Patron</th><th>Severidad</th><th>Descripcion</th><th>#</th></tr>
{% for n, info in smali_grouped.items() %}<tr><td>{{ n }}</td><td class="sev-{{ info.severity }}">{{ info.severity }}</td><td>{{ info.description }}</td><td>{{ info.count }}</td></tr>{% endfor %}
</table></div>{% endif %}
<div class="card"><h2>Estructura</h2><table>
<tr><td><strong>Archivos</strong></td><td>{{ total_files }}</td></tr>
<tr><td><strong>Tamano</strong></td><td>{{ total_size }}</td></tr>
<tr><td><strong>DEX</strong></td><td>{{ dex_count }}</td></tr>
<tr><td><strong>Libs nativas</strong></td><td>{{ native_count }}</td></tr>
<tr><td><strong>Arquitecturas</strong></td><td>{{ archs }}</td></tr>
</table>
{% if suspicious_assets %}<h3>Assets Sospechosos</h3><ul>{% for sa in suspicious_assets %}<li><code>{{ sa.path }}</code> ({{ sa.size }})</li>{% endfor %}</ul>{% endif %}
</div>
{% if ag_available %}<div class="card"><h2>Androguard - Analisis DEX</h2>
<table>
<tr><td><strong>Clases</strong></td><td>{{ ag_class_count }}</td></tr>
<tr><td><strong>Metodos</strong></td><td>{{ ag_method_count }}</td></tr>
<tr><td><strong>APIs peligrosas</strong></td><td>{{ ag_dangerous|length }}</td></tr>
<tr><td><strong>Strings interesantes</strong></td><td>{{ ag_strings|length }}</td></tr>
</table>
{% if ag_dangerous %}<h3>APIs Peligrosas</h3><table><tr><th>API</th><th>Categoria</th><th>Severidad</th></tr>
{% for a in ag_dangerous %}<tr><td><code>{{ a.api[:60] }}</code></td><td>{{ a.category }}</td><td class="sev-{{ a.severity }}">{{ a.severity }}</td></tr>{% endfor %}
</table>{% endif %}
</div>{% endif %}
{% if quark_available %}<div class="card"><h2>Quark-Engine - Heuristica Malware</h2>
<table>
<tr><td><strong>Nivel amenaza</strong></td><td class="sev-{{ quark_threat }}">{{ quark_threat }}</td></tr>
<tr><td><strong>Clasificacion</strong></td><td>{{ quark_label }}</td></tr>
<tr><td><strong>Reglas escaneadas</strong></td><td>{{ quark_scanned }}</td></tr>
<tr><td><strong>Coincidencias</strong></td><td>{{ quark_matched|length }}</td></tr>
</table>
{% if quark_behaviors %}<h3>Comportamientos Detectados</h3><table><tr><th>Comportamiento</th><th>Reglas</th></tr>
{% for b in quark_behaviors %}<tr><td>{{ b.behavior }}</td><td>{{ b.count }}</td></tr>{% endfor %}
</table>{% endif %}
</div>{% endif %}
{%- if enj_available %}<div class="card"><h2>Enjarify - Conversion DEX a JAR</h2>
<table>
<tr><td><strong>Metodo</strong></td><td>{{ enj_method }}</td></tr>
<tr><td><strong>Clases Java</strong></td><td>{{ enj_class_count }}</td></tr>
</table></div>{%- endif %}
{%- if yara_available %}<div class="card"><h2>YARA - Motor de Reglas</h2>
<table>
<tr><td><strong>Reglas cargadas</strong></td><td>{{ yara_rules_loaded }}</td></tr>
<tr><td><strong>Archivos escaneados</strong></td><td>{{ yara_files_scanned }}</td></tr>
<tr><td><strong>Coincidencias</strong></td><td>{{ yara_matches|length }}</td></tr>
</table>
{%- if yara_matches %}<h3>Detecciones</h3><table><tr><th>Regla</th><th>Categoria</th><th>Severidad</th><th>Descripcion</th></tr>
{%- for m in yara_matches %}<tr><td>{{ m.rule }}</td><td>{{ m.category }}</td><td class="sev-{{ m.severity }}">{{ m.severity }}</td><td>{{ m.description }}</td></tr>{%- endfor %}
</table>{%- endif %}
</div>{%- endif %}
{%- if apkid_available %}<div class="card"><h2>APKiD - Protecciones</h2>
{%- if apkid_packers %}<h3>Packers ({{ apkid_packers|length }})</h3><ul>{%- for p in apkid_packers %}<li>{{ p.value }}</li>{%- endfor %}</ul>{%- endif %}
{%- if apkid_obfuscators %}<h3>Ofuscadores ({{ apkid_obfuscators|length }})</h3><ul>{%- for o in apkid_obfuscators %}<li>{{ o.value }}</li>{%- endfor %}</ul>{%- endif %}
{%- if apkid_protectors %}<h3>Protectores ({{ apkid_protectors|length }})</h3><ul>{%- for p in apkid_protectors %}<li>{{ p.value }}</li>{%- endfor %}</ul>{%- endif %}
{%- if apkid_anti %}<h3>Anti-Analisis ({{ apkid_anti|length }})</h3><ul>{%- for a in apkid_anti %}<li>{{ a.value }}</li>{%- endfor %}</ul>{%- endif %}
</div>{%- endif %}
{%- if lief_available %}<div class="card"><h2>LIEF - Analisis Nativo ELF</h2>
<table>
<tr><td><strong>Total libs</strong></td><td>{{ lief_total_libs }}</td></tr>
<tr><td><strong>Imports peligrosos</strong></td><td>{{ lief_dangerous|length }}</td></tr>
<tr><td><strong>Libs sospechosas</strong></td><td>{{ lief_suspicious|length }}</td></tr>
</table>
{%- if lief_dangerous %}<h3>Imports Peligrosos</h3><table><tr><th>Funcion</th><th>Severidad</th><th>Descripcion</th></tr>
{%- for d in lief_dangerous[:20] %}<tr><td><code>{{ d.function }}</code></td><td class="sev-{{ d.severity }}">{{ d.severity }}</td><td>{{ d.description }}</td></tr>{%- endfor %}
</table>{%- endif %}
</div>{%- endif %}
</div>{%- endif %}
{%- if ep_available %}<div class="card"><h2>Endpoints - URLs, APIs y Cloud</h2>
<table>
<tr><td><strong>Total hallazgos</strong></td><td>{{ ep_total }}</td></tr>
<tr><td><strong>Dominios unicos</strong></td><td>{{ ep_domains|length }}</td></tr>
<tr><td><strong>IPs internas</strong></td><td>{{ ep_internal_ips|length }}</td></tr>
<tr><td><strong>Recursos cloud</strong></td><td>{{ ep_cloud|length }}</td></tr>
<tr><td><strong>Auth endpoints</strong></td><td>{{ ep_auth|length }}</td></tr>
</table>
{%- if ep_internal_ips %}<h3>IPs Internas</h3><table><tr><th>IP</th><th>Rango</th><th>Archivo</th></tr>
{%- for i in ep_internal_ips[:15] %}<tr><td class="sev-CRITICO"><code>{{ i.ip }}</code></td><td>{{ i.range }}</td><td><code>{{ i.file }}</code></td></tr>{%- endfor %}
</table>{%- endif %}
{%- if ep_cloud %}<h3>Recursos Cloud</h3><table><tr><th>URL</th><th>Tipo</th><th>Archivo</th></tr>
{%- for c in ep_cloud[:15] %}<tr><td><code>{{ c.url }}</code></td><td class="sev-ALTO">{{ c.get('subtype','') }}</td><td><code>{{ c.file }}</code></td></tr>{%- endfor %}
</table>{%- endif %}
{%- if ep_auth %}<h3>Auth Endpoints</h3><table><tr><th>URL/Path</th><th>Archivo</th></tr>
{%- for a in ep_auth[:15] %}<tr><td><code>{{ a.get('url','') or a.get('path','') }}</code></td><td><code>{{ a.file }}</code></td></tr>{%- endfor %}
</table>{%- endif %}
</div>{%- endif %}
{%- if inj_available %}<div class="card"><h2>Inyeccion - Vulnerabilidades</h2>
<table>
<tr><td><strong>Total</strong></td><td>{{ inj_total }}</td></tr>
<tr><td><strong>Criticos</strong></td><td class="sev-CRITICO">{{ inj_criticos|length }}</td></tr>
<tr><td><strong>Altos</strong></td><td class="sev-ALTO">{{ inj_altos|length }}</td></tr>
<tr><td><strong>Medios</strong></td><td class="sev-MEDIO">{{ inj_medios|length }}</td></tr>
<tr><td><strong>Comp. exportados vuln.</strong></td><td>{{ inj_exported|length }}</td></tr>
</table>
{%- if inj_criticos %}<h3>Criticos</h3><table><tr><th>Tipo</th><th>Descripcion</th><th>Archivo</th></tr>
{%- for v in inj_criticos[:20] %}<tr><td class="sev-CRITICO">{{ v.type }}</td><td>{{ v.description }}</td><td><code>{{ v.file }}</code></td></tr>{%- endfor %}
</table>{%- endif %}
{%- if inj_altos %}<h3>Altos</h3><table><tr><th>Tipo</th><th>Descripcion</th><th>Archivo</th></tr>
{%- for v in inj_altos[:20] %}<tr><td class="sev-ALTO">{{ v.type }}</td><td>{{ v.description }}</td><td><code>{{ v.file }}</code></td></tr>{%- endfor %}
</table>{%- endif %}
</div>{%- endif %}
{%- if cc_available %}<div class="card"><h2>Certificado X.509</h2>
{%- for c in cc_certs %}<table>
<tr><td><strong>Subject</strong></td><td><code>{{ c.subject.get('commonName','N/A') }}</code></td></tr>
<tr><td><strong>Algoritmo</strong></td><td>{{ c.get('signature_algorithm','N/A') }}</td></tr>
<tr><td><strong>Clave</strong></td><td>{{ c.get('public_key_type','') }} {{ c.get('public_key_size','') }} bits</td></tr>
<tr><td><strong>Self-signed</strong></td><td>{{ 'Si' if c.get('is_self_signed') else 'No' }}</td></tr>
<tr><td><strong>Expirado</strong></td><td class="{{ 'sev-CRITICO' if c.get('is_expired') else '' }}">{{ 'SI' if c.get('is_expired') else 'No' }}</td></tr>
<tr><td><strong>SHA256</strong></td><td><code>{{ c.get('sha256_fingerprint','N/A')[:40] }}...</code></td></tr>
</table>{%- endfor %}
{%- if cc_anomalies %}<h3>Anomalias</h3><ul>{%- for a in cc_anomalies %}<li class="sev-ALTO">{{ a }}</li>{%- endfor %}</ul>{%- endif %}
</div>{%- endif %}
{%- if owasp_available %}<div class="card"><h2>OWASP Mobile Top 10 2024</h2>
<table><tr><td><strong>Puntuación Global</strong></td><td class="sev-{{ owasp_severity }}">{{ owasp_score }}/100 - {{ owasp_severity }}</td></tr>
<tr><td><strong>Total Hallazgos</strong></td><td>{{ owasp_total }}</td></tr>
<tr><td><strong>CRITICO</strong></td><td class="sev-CRITICO">{{ owasp_criticos }}</td></tr>
<tr><td><strong>ALTO</strong></td><td class="sev-ALTO">{{ owasp_altos }}</td></tr>
<tr><td><strong>MEDIO</strong></td><td class="sev-MEDIO">{{ owasp_medios }}</td></tr>
<tr><td><strong>BAJO</strong></td><td>{{ owasp_bajos }}</td></tr></table>
<h3>Categorías</h3><table><tr><th>ID</th><th>Categoría</th><th>Severidad</th><th>Score</th><th>Hallazgos</th></tr>
{%- for cat in owasp_cats %}<tr><td><strong>{{ cat.id }}</strong></td><td>{{ cat.name }}</td><td class="sev-{{ cat.severity }}">{{ cat.severity }}</td><td>{{ cat.score }}/100</td><td>{{ cat.findings|length }}</td></tr>{%- endfor %}
</table>
{%- for cat in owasp_cats %}{%- if cat.findings %}
<h3>{{ cat.id }} - {{ cat.name }}</h3><table><tr><th>Severidad</th><th>Descripción</th><th>Evidencia</th></tr>
{%- for f in cat.findings[:10] %}<tr><td class="sev-{{ f.severity }}">{{ f.severity }}</td><td>{{ f.description }}</td><td><code>{{ f.evidence[:80] }}</code></td></tr>{%- endfor %}
</table><p><em>{{ cat.recommendation }}</em></p>{%- endif %}{%- endfor %}
</div>{%- endif %}
<div class="card"><h2>Hallazgos</h2><table><tr><th>#</th><th>Severidad</th><th>Detalle</th></tr>
{% for sev, desc in risk_findings %}<tr><td>{{ loop.index }}</td><td class="sev-{{ sev }}">{{ sev }}</td><td>{{ desc }}</td></tr>{% endfor %}
</table></div>
<footer>APKILIS v{{ version }} - Analisis Forense Android 100% Offline | {{ date }}</footer>
</div></body></html>""")

        flags = manifest.get("flags", {})
        html = tpl.render(
            app=app, date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), version=VERSION,
            risk_score=risk.get("score",0), risk_level=risk.get("level","BAJO"),
            risk_icon=risk.get("level_icon",""), risk_findings=risk.get("findings",[]),
            perms_count=len(manifest.get("permissions",[])),
            exported_count=len(manifest.get("exported_components",[])),
            trackers_count=trackers.get("total",0), total_secrets=total_secrets,
            size=file_info.get("size_human","N/A"), md5=hashes_d.get("md5",""),
            sha1=hashes_d.get("sha1",""), sha256=hashes_d.get("sha256",""),
            package=manifest.get("package",""), version_name=manifest.get("version_name",""),
            version_code=manifest.get("version_code",""), min_sdk=manifest.get("min_sdk",""),
            target_sdk=manifest.get("target_sdk",""),
            is_signed=cert.get("is_signed"), v1=cert.get("v1_signed"), v2=cert.get("v2_signed"),
            signer=cert.get("signer_info",{}),
            debuggable=flags.get("debuggable"), allow_backup=flags.get("allowBackup"),
            cleartext=flags.get("usesCleartextTraffic"),
            dangerous_perms=manifest.get("dangerous_permission_details",[]),
            exported=manifest.get("exported_components",[]),
            tracker_cats=trackers.get("by_category",{}),
            smali_grouped=smali.get("grouped",{}),
            total_files=structure.get("total_files",0), total_size=structure.get("total_size_human",""),
            dex_count=len(structure.get("dex_files",[])),
            native_count=len(structure.get("native_libs",[])),
            archs=", ".join(structure.get("architectures",[])) or "N/A",
            suspicious_assets=structure.get("suspicious_assets",[]),
            ag_available=data.get("androguard",{}).get("available", False),
            ag_class_count=data.get("androguard",{}).get("class_count", 0),
            ag_method_count=data.get("androguard",{}).get("method_count", 0),
            ag_dangerous=data.get("androguard",{}).get("dangerous_api_calls", []),
            ag_strings=data.get("androguard",{}).get("interesting_strings", []),
            quark_available=data.get("quark",{}).get("available", False),
            quark_threat=data.get("quark",{}).get("threat_level", "N/A"),
            quark_label=data.get("quark",{}).get("classification",{}).get("label", "N/A"),
            quark_scanned=data.get("quark",{}).get("rules_scanned", 0),
            quark_matched=data.get("quark",{}).get("rules_matched", []),
            quark_behaviors=data.get("quark",{}).get("behaviors_detected", []),
            enj_available=data.get("enjarify",{}).get("available", False),
            enj_method=data.get("enjarify",{}).get("method", "N/A"),
            enj_class_count=data.get("enjarify",{}).get("class_count", 0),
            # YARA
            yara_available=data.get("yara",{}).get("available", False),
            yara_rules_loaded=data.get("yara",{}).get("rules_loaded", 0),
            yara_files_scanned=data.get("yara",{}).get("files_scanned", 0),
            yara_matches=data.get("yara",{}).get("matches", []),
            # APKiD
            apkid_available=data.get("apkid",{}).get("available", False),
            apkid_packers=data.get("apkid",{}).get("packers", []),
            apkid_obfuscators=data.get("apkid",{}).get("obfuscators", []),
            apkid_protectors=data.get("apkid",{}).get("protectors", []),
            apkid_anti=data.get("apkid",{}).get("anti_analysis", []),
            # LIEF
            lief_available=data.get("lief",{}).get("available", False),
            lief_total_libs=data.get("lief",{}).get("total_libs", 0),
            lief_dangerous=data.get("lief",{}).get("dangerous_imports_found", []),
            lief_suspicious=data.get("lief",{}).get("suspicious_libs", []),
            # Endpoints
            ep_available=data.get("endpoints",{}).get("available", False),
            ep_total=data.get("endpoints",{}).get("total_endpoints", 0),
            ep_domains=data.get("endpoints",{}).get("unique_domains", []),
            ep_internal_ips=data.get("endpoints",{}).get("endpoints_by_type",{}).get("internal_ips", []),
            ep_cloud=data.get("endpoints",{}).get("endpoints_by_type",{}).get("cloud_resources", []),
            ep_auth=data.get("endpoints",{}).get("endpoints_by_type",{}).get("auth_endpoints", []),
            # Injection
            inj_available=data.get("injection",{}).get("available", False),
            inj_total=data.get("injection",{}).get("total_vulnerabilities", 0),
            inj_criticos=data.get("injection",{}).get("by_severity",{}).get("CRITICO", []),
            inj_altos=data.get("injection",{}).get("by_severity",{}).get("ALTO", []),
            inj_medios=data.get("injection",{}).get("by_severity",{}).get("MEDIO", []),
            inj_exported=data.get("injection",{}).get("exported_attack_surface", []),
            # Crypto Cert
            cc_available=data.get("crypto_cert",{}).get("available", False),
            cc_certs=data.get("crypto_cert",{}).get("certificates", []),
            cc_anomalies=data.get("crypto_cert",{}).get("cert_anomalies", []),
            # OWASP Mobile Top 10
            owasp_available=data.get("owasp_mobile",{}).get("available", False),
            owasp_score=data.get("owasp_mobile",{}).get("overall_score", 0),
            owasp_severity=data.get("owasp_mobile",{}).get("overall_severity", "N/A"),
            owasp_total=data.get("owasp_mobile",{}).get("total_findings", 0),
            owasp_criticos=data.get("owasp_mobile",{}).get("by_severity",{}).get("CRITICO", 0),
            owasp_altos=data.get("owasp_mobile",{}).get("by_severity",{}).get("ALTO", 0),
            owasp_medios=data.get("owasp_mobile",{}).get("by_severity",{}).get("MEDIO", 0),
            owasp_bajos=data.get("owasp_mobile",{}).get("by_severity",{}).get("BAJO", 0),
            owasp_cats=data.get("owasp_mobile",{}).get("categories", []),
        )

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path

# ====================================================================
# MODULO: STRING DEOBFUSCATION - DECODIFICACION AUTOMATICA DE STRINGS
# ====================================================================

class StringDeobfuscator:
    """Detecta y decodifica strings ofuscadas (Base64, hex, XOR, ROT13, URL-encode) en smali/java."""

    B64_RE = re.compile(r'\"([A-Za-z0-9+/]{20,}={0,2})\"')
    HEX_RE = re.compile(r'\"((?:[0-9a-fA-F]{2}){8,})\"')
    URLENC_RE = re.compile(r'\"(%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}|[\w./:?&=-]){6,})\"')
    UNICODE_ESC_RE = re.compile(r'\"((?:\\u[0-9a-fA-F]{4}){4,})\"')

    INTERESTING_DECODED = re.compile(
        r'(?:https?://|ftp://|ws://|wss://|file://|content://'
        r'|\.onion|\.i2p'
        r'|BEGIN\s+(?:RSA|CERTIFICATE|PRIVATE)'
        r'|password|passwd|secret|token|api.?key|auth'
        r'|SELECT\s|INSERT\s|DROP\s|UNION\s'
        r'|/etc/passwd|/system/bin|/data/data'
        r'|exec\(|eval\(|Runtime|ProcessBuilder'
        r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.IGNORECASE
    )

    @staticmethod
    def analyze(decompiled_dir, jadx_dir=None):
        import base64
        from urllib.parse import unquote

        result = {
            "available": False,
            "total_decoded": 0,
            "interesting_strings": [],
            "by_encoding": {"base64": 0, "hex": 0, "url_encoded": 0, "unicode_escape": 0, "rot13": 0},
            "by_severity": {"CRITICO": [], "ALTO": [], "MEDIO": [], "INFO": []},
            "summary": "",
        }

        dirs_to_scan = []
        if decompiled_dir and os.path.isdir(decompiled_dir):
            dirs_to_scan.append(decompiled_dir)
        if jadx_dir and os.path.isdir(jadx_dir):
            dirs_to_scan.append(jadx_dir)
        if not dirs_to_scan:
            result["summary"] = "No hay directorios decompilados para analizar"
            return result

        result["available"] = True
        decoded_set = set()

        def _classify(decoded, encoding, file_path, original):
            if decoded in decoded_set or len(decoded) < 6:
                return
            decoded_set.add(decoded)
            result["total_decoded"] += 1
            result["by_encoding"][encoding] = result["by_encoding"].get(encoding, 0) + 1

            if StringDeobfuscator.INTERESTING_DECODED.search(decoded):
                if any(kw in decoded.lower() for kw in ("exec(", "eval(", "runtime", "processbuilder",
                                                          ".onion", "/etc/passwd", "drop ")):
                    severity = "CRITICO"
                elif any(kw in decoded.lower() for kw in ("http://", "https://", "ftp://", "ws://",
                                                           "password", "secret", "token", "api_key",
                                                           "apikey", "api-key", "begin rsa", "begin private")):
                    severity = "ALTO"
                else:
                    severity = "MEDIO"

                entry = {
                    "decoded": decoded[:200],
                    "encoding": encoding,
                    "original": original[:120],
                    "file": os.path.basename(file_path),
                    "severity": severity,
                }
                result["interesting_strings"].append(entry)
                result["by_severity"][severity].append(entry)

        for scan_dir in dirs_to_scan:
            for root, _, files in os.walk(scan_dir):
                for fname in files:
                    if not fname.endswith(('.smali', '.java', '.xml', '.json')):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(512_000)  # max 500KB per file
                    except Exception:
                        continue

                    # Base64
                    for m in StringDeobfuscator.B64_RE.finditer(content):
                        raw = m.group(1)
                        try:
                            decoded = base64.b64decode(raw).decode('utf-8', errors='ignore')
                            if decoded.isprintable() and len(decoded) > 5:
                                _classify(decoded, "base64", fpath, raw)
                        except Exception:
                            pass

                    # Hex
                    for m in StringDeobfuscator.HEX_RE.finditer(content):
                        raw = m.group(1)
                        try:
                            decoded = bytes.fromhex(raw).decode('utf-8', errors='ignore')
                            if decoded.isprintable() and len(decoded) > 5:
                                _classify(decoded, "hex", fpath, raw)
                        except Exception:
                            pass

                    # URL-encoded
                    for m in StringDeobfuscator.URLENC_RE.finditer(content):
                        raw = m.group(1)
                        try:
                            decoded = unquote(raw)
                            if decoded != raw and len(decoded) > 5:
                                _classify(decoded, "url_encoded", fpath, raw)
                        except Exception:
                            pass

                    # Unicode escape
                    for m in StringDeobfuscator.UNICODE_ESC_RE.finditer(content):
                        raw = m.group(1)
                        try:
                            decoded = raw.encode('utf-8').decode('unicode_escape')
                            if decoded.isprintable() and len(decoded) > 3:
                                _classify(decoded, "unicode_escape", fpath, raw)
                        except Exception:
                            pass

                    # ROT13 on suspicious-looking quoted strings (short heuristic)
                    for m in re.finditer(r'\"([a-zA-Z]{12,60})\"', content):
                        raw = m.group(1)
                        import codecs
                        decoded = codecs.decode(raw, 'rot_13')
                        if StringDeobfuscator.INTERESTING_DECODED.search(decoded):
                            _classify(decoded, "rot13", fpath, raw)

        crit = len(result["by_severity"]["CRITICO"])
        alto = len(result["by_severity"]["ALTO"])
        result["summary"] = (
            f"Decodificadas: {result['total_decoded']} strings | "
            f"Interesantes: {len(result['interesting_strings'])} "
            f"({crit} críticas, {alto} altas)"
        )
        logger.info(f"StringDeobfuscator: {result['summary']}")
        return result


# ====================================================================
# MODULO: APK SIGNATURE SCHEME CHECKER
# ====================================================================

class SignatureSchemeChecker:
    """Verifica esquemas de firma APK v1/v2/v3/v4 y detecta vulnerabilidad Janus."""

    @staticmethod
    def analyze(apk_path, decompiled_dir=None):
        result = {
            "available": False,
            "schemes": {"v1": False, "v2": False, "v3": False, "v4": False},
            "scheme_details": [],
            "vulnerabilities": [],
            "janus_vulnerable": False,
            "signature_files": [],
            "summary": "",
        }

        if not os.path.isfile(apk_path):
            return result

        result["available"] = True

        # Detect signature schemes by inspecting APK structure
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                names = zf.namelist()

                # v1: JAR signature (META-INF/*.SF, *.RSA, *.DSA, *.EC)
                meta_inf = [n for n in names if n.startswith("META-INF/")]
                sf_files = [n for n in meta_inf if n.upper().endswith('.SF')]
                sig_files = [n for n in meta_inf if n.upper().endswith(('.RSA', '.DSA', '.EC'))]
                if sf_files and sig_files:
                    result["schemes"]["v1"] = True
                    result["signature_files"] = sf_files + sig_files
                    result["scheme_details"].append({
                        "scheme": "v1 (JAR)",
                        "detected": True,
                        "files": sf_files + sig_files,
                    })

                    # Check MANIFEST.MF for completeness
                    manifest_mf = [n for n in meta_inf if n.upper() == "META-INF/MANIFEST.MF"]
                    if manifest_mf:
                        mf_content = zf.read(manifest_mf[0]).decode('utf-8', errors='ignore')
                        entry_count = mf_content.count("Name: ")
                        file_count = len([n for n in names if not n.startswith("META-INF/") and not n.endswith('/')])
                        if entry_count < file_count * 0.9:
                            result["vulnerabilities"].append({
                                "id": "PARTIAL_V1_SIGNING",
                                "severity": "ALTO",
                                "description": f"Firma v1 parcial: {entry_count} entradas vs {file_count} archivos - archivos sin firmar pueden ser modificados",
                            })
                else:
                    result["scheme_details"].append({"scheme": "v1 (JAR)", "detected": False})

        except zipfile.BadZipFile:
            result["vulnerabilities"].append({
                "id": "CORRUPT_ZIP",
                "severity": "CRITICO",
                "description": "Archivo ZIP corrupto o manipulado",
            })
            return result

        # v2/v3: APK Signing Block detection (binary analysis)
        try:
            with open(apk_path, 'rb') as f:
                data = f.read()

                # Find ZIP End of Central Directory
                eocd_pos = data.rfind(b'\x50\x4b\x05\x06')
                if eocd_pos > 0:
                    cd_offset = int.from_bytes(data[eocd_pos + 16:eocd_pos + 20], 'little')

                    # APK Signing Block is right before Central Directory
                    # It ends with magic: "APK Sig Block 42"
                    magic = b'APK Sig Block 42'
                    search_start = max(0, cd_offset - 4096)
                    block_pos = data.find(magic, search_start, cd_offset + 16)

                    if block_pos > 0:
                        # v2 scheme ID: 0x7109871a
                        if data.find(b'\x1a\x87\x09\x71', search_start, block_pos) > 0:
                            result["schemes"]["v2"] = True
                            result["scheme_details"].append({"scheme": "v2 (Full APK)", "detected": True})
                        else:
                            result["scheme_details"].append({"scheme": "v2 (Full APK)", "detected": False})

                        # v3 scheme ID: 0xf05368c0
                        if data.find(b'\xc0\x68\x53\xf0', search_start, block_pos) > 0:
                            result["schemes"]["v3"] = True
                            result["scheme_details"].append({"scheme": "v3 (Key Rotation)", "detected": True})
                        else:
                            result["scheme_details"].append({"scheme": "v3 (Key Rotation)", "detected": False})
                    else:
                        result["scheme_details"].append({"scheme": "v2 (Full APK)", "detected": False})
                        result["scheme_details"].append({"scheme": "v3 (Key Rotation)", "detected": False})

        except Exception as e:
            logger.debug(f"SignatureScheme: error leyendo bloques binarios: {e}")

        # v4: .idsig file check
        idsig_path = apk_path + ".idsig"
        if os.path.isfile(idsig_path):
            result["schemes"]["v4"] = True
            result["scheme_details"].append({"scheme": "v4 (Incremental)", "detected": True})
        else:
            result["scheme_details"].append({"scheme": "v4 (Incremental)", "detected": False})

        # Janus vulnerability (CVE-2017-13156): DEX+ZIP polyglot
        try:
            with open(apk_path, 'rb') as f:
                header = f.read(8)
                # DEX magic: "dex\n035\0" or "dex\n037\0" etc.
                if header[:4] == b'dex\n':
                    result["janus_vulnerable"] = True
                    result["vulnerabilities"].append({
                        "id": "JANUS_CVE-2017-13156",
                        "severity": "CRITICO",
                        "description": "APK comienza con header DEX - vulnerable a Janus (CVE-2017-13156). "
                                       "Permite inyectar código sin invalidar la firma v1.",
                    })
        except Exception:
            pass

        # Security assessments
        if result["schemes"]["v1"] and not result["schemes"]["v2"]:
            result["vulnerabilities"].append({
                "id": "V1_ONLY",
                "severity": "ALTO",
                "description": "Solo firma v1 detectada. Vulnerable a ZipperDown y modificaciones "
                               "de archivos no listados en MANIFEST.MF. Se recomienda v2+.",
            })

        if not any(result["schemes"].values()):
            result["vulnerabilities"].append({
                "id": "NO_SIGNATURE",
                "severity": "CRITICO",
                "description": "No se detectó ningún esquema de firma válido",
            })

        schemes_str = ", ".join(f"{k}={'✓' if v else '✗'}" for k, v in result["schemes"].items())
        result["summary"] = (
            f"Esquemas: {schemes_str} | "
            f"Vulnerabilidades: {len(result['vulnerabilities'])}"
        )
        logger.info(f"SignatureScheme: {result['summary']}")
        return result


# ====================================================================
# MODULO: DEEP RESOURCE ANALYZER
# ====================================================================

class DeepResourceAnalyzer:
    """Analiza recursos embebidos: SQLite preloaded, configs ocultas, binarios en assets/raw."""

    SUSPICIOUS_EXTENSIONS = {
        '.dex': ('CRITICO', 'Archivo DEX adicional (posible payload)'),
        '.so': ('ALTO', 'Librería nativa embebida en recursos'),
        '.jar': ('ALTO', 'Archivo JAR embebido'),
        '.apk': ('CRITICO', 'APK embebido (posible dropper)'),
        '.elf': ('CRITICO', 'Binario ELF embebido'),
        '.sh': ('ALTO', 'Script shell embebido'),
        '.bin': ('MEDIO', 'Archivo binario genérico'),
        '.dat': ('MEDIO', 'Archivo de datos (posible payload cifrado)'),
        '.enc': ('ALTO', 'Archivo cifrado (posible payload)'),
        '.zip': ('MEDIO', 'Archivo ZIP embebido'),
        '.db': ('MEDIO', 'Base de datos SQLite preloaded'),
        '.sqlite': ('MEDIO', 'Base de datos SQLite preloaded'),
    }

    @staticmethod
    def analyze(apk_path, decompiled_dir=None):
        import sqlite3 as _sqlite3

        result = {
            "available": False,
            "suspicious_resources": [],
            "hidden_configs": [],
            "embedded_databases": [],
            "embedded_executables": [],
            "large_assets": [],
            "by_severity": {"CRITICO": [], "ALTO": [], "MEDIO": [], "INFO": []},
            "summary": "",
        }

        if not os.path.isfile(apk_path):
            return result

        result["available"] = True

        # Scan inside ZIP for suspicious entries
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    name_lower = info.filename.lower()
                    ext = os.path.splitext(name_lower)[1]

                    # Large assets (>500KB)
                    if info.file_size > 512_000 and ('assets/' in name_lower or 'res/raw/' in name_lower):
                        result["large_assets"].append({
                            "path": info.filename,
                            "size": info.file_size,
                            "compressed": info.compress_size,
                            "ratio": round(info.compress_size / max(info.file_size, 1), 3),
                        })

                    # Suspicious file types
                    if ext in DeepResourceAnalyzer.SUSPICIOUS_EXTENSIONS:
                        severity, desc = DeepResourceAnalyzer.SUSPICIOUS_EXTENSIONS[ext]
                        # DEX outside root is more suspicious
                        if ext == '.dex' and info.filename.startswith('classes'):
                            continue  # normal DEX files
                        entry = {
                            "path": info.filename,
                            "extension": ext,
                            "size": info.file_size,
                            "severity": severity,
                            "description": desc,
                        }
                        result["suspicious_resources"].append(entry)
                        result["by_severity"][severity].append(entry)

                        if ext in ('.dex', '.so', '.elf', '.apk', '.jar', '.sh'):
                            result["embedded_executables"].append(entry)

                    # Hidden configs (JSON/XML in assets with suspicious names)
                    if ('assets/' in name_lower or 'res/raw/' in name_lower):
                        basename = os.path.basename(name_lower)
                        if ext in ('.json', '.xml', '.cfg', '.conf', '.ini', '.properties', '.yml', '.yaml'):
                            try:
                                raw = zf.read(info.filename)
                                text = raw.decode('utf-8', errors='ignore')[:10_000]
                                suspicious_keys = re.findall(
                                    r'(?:api[_-]?key|secret|password|token|endpoint|server|host|url|'
                                    r'base[_-]?url|webhook|callback|remote|c2|command)[\s]*[=:"\']+\s*([^\s"\'<>,;]{4,})',
                                    text, re.IGNORECASE
                                )
                                if suspicious_keys:
                                    config_entry = {
                                        "path": info.filename,
                                        "type": ext.lstrip('.'),
                                        "suspicious_keys": suspicious_keys[:10],
                                        "severity": "ALTO",
                                    }
                                    result["hidden_configs"].append(config_entry)
                                    result["by_severity"]["ALTO"].append(config_entry)
                            except Exception:
                                pass

                    # SQLite databases in assets
                    if ext in ('.db', '.sqlite', '.sqlite3') or basename in ('database', 'data'):
                        try:
                            raw = zf.read(info.filename)
                            if raw[:16].startswith(b'SQLite format 3'):
                                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                                tmp.write(raw)
                                tmp.close()
                                try:
                                    conn = _sqlite3.connect(tmp.name)
                                    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                                    tables = [r[0] for r in cursor.fetchall()]
                                    row_counts = {}
                                    for t in tables[:20]:
                                        try:
                                            c2 = conn.execute(f'SELECT COUNT(*) FROM "{t}"')
                                            row_counts[t] = c2.fetchone()[0]
                                        except Exception:
                                            row_counts[t] = -1
                                    conn.close()
                                    db_entry = {
                                        "path": info.filename,
                                        "size": info.file_size,
                                        "tables": tables,
                                        "row_counts": row_counts,
                                        "severity": "MEDIO",
                                    }
                                    result["embedded_databases"].append(db_entry)
                                    result["by_severity"]["MEDIO"].append(db_entry)
                                finally:
                                    os.unlink(tmp.name)
                        except Exception:
                            pass

                    # High entropy detection (possible encrypted payloads)
                    if info.file_size > 1024 and ext in ('.bin', '.dat', '.enc', '.raw', '.blob'):
                        try:
                            sample = zf.read(info.filename)[:4096]
                            import math
                            freq = [0] * 256
                            for b in sample:
                                freq[b] += 1
                            length = len(sample)
                            entropy = -sum((c/length) * math.log2(c/length) for c in freq if c > 0)
                            if entropy > 7.5:
                                enc_entry = {
                                    "path": info.filename,
                                    "size": info.file_size,
                                    "entropy": round(entropy, 3),
                                    "severity": "ALTO",
                                    "description": f"Archivo con alta entropía ({entropy:.2f}) - posible payload cifrado",
                                }
                                result["suspicious_resources"].append(enc_entry)
                                result["by_severity"]["ALTO"].append(enc_entry)
                        except Exception:
                            pass

        except Exception as e:
            logger.debug(f"DeepResourceAnalyzer: {e}")

        crit = len(result["by_severity"]["CRITICO"])
        alto = len(result["by_severity"]["ALTO"])
        result["summary"] = (
            f"Recursos sospechosos: {len(result['suspicious_resources'])} | "
            f"Configs ocultas: {len(result['hidden_configs'])} | "
            f"DBs embebidas: {len(result['embedded_databases'])} | "
            f"Ejecutables: {len(result['embedded_executables'])} "
            f"({crit} críticos, {alto} altos)"
        )
        logger.info(f"DeepResourceAnalyzer: {result['summary']}")
        return result


# ====================================================================
# MODULO: ACCESSIBILITY / OVERLAY ABUSE DETECTOR
# ====================================================================

class AccessibilityOverlayAnalyzer:
    """Detecta abuso de AccessibilityService y TYPE_APPLICATION_OVERLAY (troyanos bancarios)."""

    # Smali/Java patterns for accessibility abuse
    A11Y_PATTERNS = {
        "AccessibilityService_Decl": {
            "pattern": re.compile(r'android[./]accessibilityservice[./]AccessibilityService', re.IGNORECASE),
            "severity": "ALTO",
            "desc": "Declara/extiende AccessibilityService",
        },
        "A11y_Event_Dispatch": {
            "pattern": re.compile(r'(?:onAccessibilityEvent|performAction|performGlobalAction)', re.IGNORECASE),
            "severity": "ALTO",
            "desc": "Maneja eventos de accesibilidad (posible keylogging/auto-click)",
        },
        "A11y_Node_Traversal": {
            "pattern": re.compile(r'(?:getRootInActiveWindow|findAccessibilityNodeInfo|getChild\()', re.IGNORECASE),
            "severity": "ALTO",
            "desc": "Navega árbol de nodos UI (screen scraping)",
        },
        "A11y_Text_Extraction": {
            "pattern": re.compile(r'(?:getText\(\)|getContentDescription\(\)|AccessibilityNodeInfo.*text)', re.IGNORECASE),
            "severity": "CRITICO",
            "desc": "Extrae texto de la UI (posible robo de credenciales)",
        },
        "A11y_Click_Inject": {
            "pattern": re.compile(r'(?:ACTION_CLICK|ACTION_SCROLL|ACTION_SET_TEXT|performAction\(|dispatchGesture)', re.IGNORECASE),
            "severity": "CRITICO",
            "desc": "Inyecta clicks/gestos (auto-confirmación sin consentimiento)",
        },
        "Overlay_Window": {
            "pattern": re.compile(r'(?:TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|TYPE_SYSTEM_OVERLAY|TYPE_PHONE)', re.IGNORECASE),
            "severity": "CRITICO",
            "desc": "Crea ventana overlay (posible phishing overlay)",
        },
        "Draw_Over_Apps": {
            "pattern": re.compile(r'(?:SYSTEM_ALERT_WINDOW|canDrawOverlays|ACTION_MANAGE_OVERLAY)', re.IGNORECASE),
            "severity": "ALTO",
            "desc": "Solicita/verifica permiso de dibujar sobre otras apps",
        },
        "WindowManager_Overlay": {
            "pattern": re.compile(r'WindowManager.*addView|LayoutParams.*(?:TYPE_APPLICATION_OVERLAY|FLAG_NOT_TOUCHABLE)', re.IGNORECASE),
            "severity": "CRITICO",
            "desc": "Agrega vista overlay via WindowManager",
        },
        "Keylogger_Pattern": {
            "pattern": re.compile(r'(?:onKey|dispatchKeyEvent|KeyEvent|InputConnection.*(?:getText|commitText))', re.IGNORECASE),
            "severity": "ALTO",
            "desc": "Intercepta eventos de teclado (posible keylogger)",
        },
        "Screen_Capture": {
            "pattern": re.compile(r'(?:MediaProjection|createScreenCapture|CAPTURE_VIDEO_OUTPUT|createVirtualDisplay)', re.IGNORECASE),
            "severity": "CRITICO",
            "desc": "Captura de pantalla (posible grabación)",
        },
    }

    @staticmethod
    def analyze(manifest_data, decompiled_dir=None, jadx_dir=None):
        result = {
            "available": False,
            "has_accessibility_service": False,
            "has_overlay_permission": False,
            "accessibility_config": {},
            "code_findings": [],
            "risk_indicators": [],
            "by_severity": {"CRITICO": [], "ALTO": [], "MEDIO": [], "INFO": []},
            "risk_level": "BAJO",
            "summary": "",
        }

        # Check manifest for accessibility declarations
        permissions = [p if isinstance(p, str) else p.get("name", "") for p in manifest_data.get("permissions", [])]
        perm_names = [p.upper() for p in permissions]

        if "BIND_ACCESSIBILITY_SERVICE" in " ".join(perm_names) or \
           any("accessibilityservice" in str(c).lower() for c in manifest_data.get("services", manifest_data.get("exported_components", []))):
            result["has_accessibility_service"] = True
            result["risk_indicators"].append({
                "indicator": "Declara AccessibilityService en manifest",
                "severity": "ALTO",
                "detail": "Puede leer/interactuar con la UI de otras apps",
            })

        if any("SYSTEM_ALERT_WINDOW" in p for p in perm_names):
            result["has_overlay_permission"] = True
            result["risk_indicators"].append({
                "indicator": "Permiso SYSTEM_ALERT_WINDOW",
                "severity": "ALTO",
                "detail": "Puede dibujar ventanas sobre otras apps (overlay attacks)",
            })

        if not result["has_accessibility_service"] and not result["has_overlay_permission"]:
            result["available"] = True
            result["summary"] = "Sin servicios de accesibilidad ni overlays detectados"
            return result

        result["available"] = True

        # Scan code for abuse patterns
        dirs_to_scan = []
        if decompiled_dir and os.path.isdir(decompiled_dir):
            dirs_to_scan.append(decompiled_dir)
        if jadx_dir and os.path.isdir(jadx_dir):
            dirs_to_scan.append(jadx_dir)

        for scan_dir in dirs_to_scan:
            for root, _, files in os.walk(scan_dir):
                for fname in files:
                    if not fname.endswith(('.smali', '.java', '.xml')):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(512_000)
                    except Exception:
                        continue

                    for name, info in AccessibilityOverlayAnalyzer.A11Y_PATTERNS.items():
                        matches = info["pattern"].findall(content)
                        if matches:
                            entry = {
                                "pattern": name,
                                "severity": info["severity"],
                                "description": info["desc"],
                                "file": os.path.relpath(fpath, scan_dir),
                                "count": len(matches),
                            }
                            result["code_findings"].append(entry)
                            result["by_severity"][info["severity"]].append(entry)

        # Determine combined risk
        crit = len(result["by_severity"]["CRITICO"])
        alto = len(result["by_severity"]["ALTO"])

        if crit > 0 and result["has_accessibility_service"]:
            result["risk_level"] = "CRITICO"
            result["risk_indicators"].append({
                "indicator": "AccessibilityService + patrones de abuso críticos",
                "severity": "CRITICO",
                "detail": f"{crit} patrones críticos detectados con servicio de accesibilidad activo - "
                          "comportamiento consistente con troyano bancario",
            })
        elif result["has_accessibility_service"] and result["has_overlay_permission"]:
            result["risk_level"] = "CRITICO"
            result["risk_indicators"].append({
                "indicator": "Accesibilidad + Overlay = vector de ataque bancario",
                "severity": "CRITICO",
                "detail": "Combinación de accesibilidad y overlay es el patrón principal de troyanos bancarios Android",
            })
        elif crit > 0:
            result["risk_level"] = "ALTO"
        elif alto > 2:
            result["risk_level"] = "ALTO"
        elif alto > 0 or result["has_accessibility_service"]:
            result["risk_level"] = "MEDIO"

        result["summary"] = (
            f"Accesibilidad: {'SÍ' if result['has_accessibility_service'] else 'NO'} | "
            f"Overlay: {'SÍ' if result['has_overlay_permission'] else 'NO'} | "
            f"Hallazgos: {len(result['code_findings'])} "
            f"({crit} críticos, {alto} altos) | "
            f"Riesgo: {result['risk_level']}"
        )
        logger.info(f"AccessibilityOverlay: {result['summary']}")
        return result


# ====================================================================
# MODULO: INTENT / IPC ATTACK SURFACE ANALYZER
# ====================================================================

class IntentIPCAnalyzer:
    """Mapea superficies de ataque IPC: componentes exportados, deep links, intent-filters explotables."""

    DANGEROUS_ACTIONS = {
        "android.intent.action.INSTALL_PACKAGE": ("CRITICO", "Instala paquetes (posible dropper)"),
        "android.intent.action.DELETE": ("ALTO", "Desinstala paquetes"),
        "android.intent.action.SEND": ("MEDIO", "Envío de datos (posible exfiltración)"),
        "android.intent.action.SENDTO": ("MEDIO", "Envío dirigido de datos"),
        "android.intent.action.CALL": ("ALTO", "Realiza llamadas telefónicas"),
        "android.intent.action.SEND_MULTIPLE": ("MEDIO", "Envío múltiple de datos"),
    }

    DANGEROUS_SCHEMES = {
        "javascript": ("CRITICO", "Scheme javascript: - posible XSS via WebView"),
        "file": ("ALTO", "Scheme file: - acceso al filesystem"),
        "content": ("MEDIO", "Scheme content: - acceso a content providers"),
        "data": ("ALTO", "Scheme data: - posible inyección de datos"),
    }

    @staticmethod
    def analyze(manifest_data, decompiled_dir=None):
        result = {
            "available": False,
            "exported_activities": [],
            "exported_services": [],
            "exported_receivers": [],
            "exported_providers": [],
            "deep_links": [],
            "dangerous_intents": [],
            "unprotected_components": [],
            "pending_intent_risks": [],
            "by_severity": {"CRITICO": [], "ALTO": [], "MEDIO": [], "INFO": []},
            "attack_surface_score": 0,
            "summary": "",
        }

        result["available"] = True

        # Analyze exported components from manifest
        exported = manifest_data.get("exported_components", [])
        for comp in exported:
            comp_type = comp.get("type", "unknown")
            comp_name = comp.get("name", "")
            is_protected = comp.get("protected", False)

            target_list = {
                "activity": result["exported_activities"],
                "service": result["exported_services"],
                "receiver": result["exported_receivers"],
                "provider": result["exported_providers"],
            }.get(comp_type, [])

            entry = {
                "name": comp_name,
                "type": comp_type,
                "protected": is_protected,
                "permission": comp.get("permission", ""),
                "intent_filters": comp.get("intent_filters", []),
            }
            target_list.append(entry)

            if not is_protected:
                result["unprotected_components"].append(entry)
                severity = "ALTO" if comp_type in ("service", "provider") else "MEDIO"
                vuln = {
                    "component": comp_name,
                    "type": comp_type,
                    "severity": severity,
                    "description": f"Componente {comp_type} exportado sin permiso de protección",
                }
                result["by_severity"][severity].append(vuln)

            # Check intent filters for deep links
            for ifilter in comp.get("intent_filters", []):
                actions = ifilter if isinstance(ifilter, list) else [ifilter]
                for action_str in actions:
                    if isinstance(action_str, str) and action_str in IntentIPCAnalyzer.DANGEROUS_ACTIONS:
                        sev, desc = IntentIPCAnalyzer.DANGEROUS_ACTIONS[action_str]
                        danger = {
                            "component": comp_name,
                            "action": action_str,
                            "severity": sev,
                            "description": desc,
                        }
                        result["dangerous_intents"].append(danger)
                        result["by_severity"][sev].append(danger)

        # Parse AndroidManifest.xml directly for deep links and schemes
        if decompiled_dir:
            manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
            if os.path.isfile(manifest_path):
                try:
                    with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                        manifest_xml = f.read()

                    # Extract deep link schemes
                    import xml.etree.ElementTree as ET
                    try:
                        root = ET.fromstring(manifest_xml)
                        ns = {'android': 'http://schemas.android.com/apk/res/android'}

                        for activity in root.iter('activity'):
                            act_name = activity.get(f'{{{ns["android"]}}}name', 'unknown')
                            for intent_filter in activity.iter('intent-filter'):
                                for data_elem in intent_filter.iter('data'):
                                    scheme = data_elem.get(f'{{{ns["android"]}}}scheme', '')
                                    host = data_elem.get(f'{{{ns["android"]}}}host', '')
                                    path = data_elem.get(f'{{{ns["android"]}}}path', '')
                                    pathPrefix = data_elem.get(f'{{{ns["android"]}}}pathPrefix', '')

                                    if scheme:
                                        deep_link = {
                                            "activity": act_name,
                                            "scheme": scheme,
                                            "host": host,
                                            "path": path or pathPrefix,
                                            "full_uri": f"{scheme}://{host}{path or pathPrefix}",
                                        }
                                        result["deep_links"].append(deep_link)

                                        if scheme.lower() in IntentIPCAnalyzer.DANGEROUS_SCHEMES:
                                            sev, desc = IntentIPCAnalyzer.DANGEROUS_SCHEMES[scheme.lower()]
                                            vuln = {
                                                "activity": act_name,
                                                "scheme": scheme,
                                                "severity": sev,
                                                "description": desc,
                                            }
                                            result["dangerous_intents"].append(vuln)
                                            result["by_severity"][sev].append(vuln)

                        # Content providers with grantUriPermissions
                        for provider in root.iter('provider'):
                            prov_name = provider.get(f'{{{ns["android"]}}}name', 'unknown')
                            exported = provider.get(f'{{{ns["android"]}}}exported', 'false')
                            grant_uri = provider.get(f'{{{ns["android"]}}}grantUriPermissions', 'false')
                            if exported == 'true' and grant_uri == 'true':
                                vuln = {
                                    "component": prov_name,
                                    "severity": "ALTO",
                                    "description": "ContentProvider exportado con grantUriPermissions=true - "
                                                   "posible path traversal / data leak",
                                }
                                result["by_severity"]["ALTO"].append(vuln)

                    except ET.ParseError:
                        # Fallback regex for broken XML
                        schemes_found = re.findall(r'android:scheme="([^"]+)"', manifest_xml)
                        hosts_found = re.findall(r'android:host="([^"]+)"', manifest_xml)
                        for s in schemes_found:
                            result["deep_links"].append({"scheme": s, "host": hosts_found[0] if hosts_found else ""})

                except Exception as e:
                    logger.debug(f"IntentIPC: error parsing manifest: {e}")

        # Scan smali for PendingIntent risks
        if decompiled_dir and os.path.isdir(decompiled_dir):
            pending_re = re.compile(r'PendingIntent\.(?:getActivity|getService|getBroadcast)\(')
            implicit_re = re.compile(r'new-instance\s+v\d+,\s+Landroid/content/Intent;.*?'
                                     r'invoke-direct.*?<init>\(\)V', re.DOTALL)
            for root, _, files in os.walk(decompiled_dir):
                for fname in files:
                    if not fname.endswith('.smali'):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(256_000)
                    except Exception:
                        continue

                    # PendingIntent with implicit intent
                    if pending_re.search(content) and implicit_re.search(content):
                        vuln = {
                            "file": os.path.relpath(fpath, decompiled_dir),
                            "severity": "ALTO",
                            "description": "PendingIntent con Intent implícito - posible intent hijacking",
                        }
                        result["pending_intent_risks"].append(vuln)
                        result["by_severity"]["ALTO"].append(vuln)

        # Calculate attack surface score
        score = 0
        score += len(result["unprotected_components"]) * 5
        score += len(result["dangerous_intents"]) * 10
        score += len(result["deep_links"]) * 2
        score += len(result["pending_intent_risks"]) * 8
        score += len(result["by_severity"]["CRITICO"]) * 15
        result["attack_surface_score"] = min(score, 100)

        crit = len(result["by_severity"]["CRITICO"])
        alto = len(result["by_severity"]["ALTO"])
        result["summary"] = (
            f"Componentes sin proteger: {len(result['unprotected_components'])} | "
            f"Deep links: {len(result['deep_links'])} | "
            f"Intents peligrosos: {len(result['dangerous_intents'])} | "
            f"PendingIntent riesgosos: {len(result['pending_intent_risks'])} | "
            f"Score: {result['attack_surface_score']}/100"
        )
        logger.info(f"IntentIPC: {result['summary']}")
        return result


# ====================================================================
# MODULO: DETECCION DE BACKDOORS Y C2
# ====================================================================

class BackdoorC2Detector:
    """Detecta patrones de backdoor, C2 callbacks, DGA, beacons y spyware en smali."""

    @staticmethod
    def analyze(decompiled_dir):
        findings = []
        smali_files = []
        for root, _, files in os.walk(decompiled_dir):
            for f in files:
                if f.endswith('.smali'):
                    smali_files.append(os.path.join(root, f))

        compiled = {}
        for name, info in BACKDOOR_C2_PATTERNS.items():
            try:
                compiled[name] = (re.compile(info["pattern"], re.DOTALL),
                                  info["severity"], info["desc"], info["category"])
            except re.error:
                continue

        files_with_hits = set()
        for smali_file in smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                rel_path = os.path.relpath(smali_file, decompiled_dir)

                for name, (pattern, severity, desc, category) in compiled.items():
                    matches = pattern.findall(content)
                    if matches:
                        findings.append({
                            "name": name, "severity": severity,
                            "description": desc, "category": category,
                            "file": rel_path, "count": len(matches),
                        })
                        files_with_hits.add(rel_path)

                # Detección heurística adicional: strings sospechosos de C2
                BackdoorC2Detector._check_c2_strings(content, rel_path, findings)
            except Exception as e:
                logger.debug(f"Error en BackdoorC2Detector para {smali_file}: {e}")
                continue

        by_category = defaultdict(list)
        for f in findings:
            by_category[f["category"]].append(f)

        return {
            "available": True,
            "findings": findings,
            "by_category": dict(by_category),
            "total_findings": len(findings),
            "files_with_backdoor_indicators": len(files_with_hits),
            "has_backdoor_indicators": any(
                f["category"] in ("backdoor", "c2_beacon", "c2_encrypted", "dga", "c2_sms", "c2_raw")
                for f in findings
            ),
            "has_spyware_indicators": any(
                f["category"] in ("spyware", "keylogger", "exfiltration")
                for f in findings
            ),
            "has_exfiltration": any(
                f["category"] == "exfiltration" for f in findings
            ),
        }

    @staticmethod
    def _check_c2_strings(content, rel_path, findings):
        """Busca strings típicos de C2 hardcodeados en smali."""
        c2_indicators = [
            (r'const-string.*?"cmd"', "Referencia a 'cmd' (command execution)"),
            (r'const-string.*?"shell"', "Referencia a 'shell' (command execution)"),
            (r'const-string.*?"/bin/sh"', "Ruta a /bin/sh (shell local)"),
            (r'const-string.*?"reverse".*?"connect"', "Strings 'reverse'+'connect' (reverse shell)"),
            (r'const-string.*?"heartbeat"', "String 'heartbeat' (C2 beacon)"),
            (r'const-string.*?"beacon"', "String 'beacon' (C2 pattern)"),
            (r'const-string.*?"callback".*?const-string.*?"http"', "Callback HTTP (C2)"),
            (r'const-string.*?"rat"', "String 'RAT' (Remote Access Trojan)"),
            (r'const-string.*?"botnet"', "String 'botnet'"),
            (r'const-string.*?"payload".*?const-string.*?"exec"', "Payload + exec (dropper)"),
        ]
        for pattern_str, desc in c2_indicators:
            try:
                if re.search(pattern_str, content, re.IGNORECASE | re.DOTALL):
                    findings.append({
                        "name": f"C2_String_{desc[:20].replace(' ', '_')}",
                        "severity": "ALTO",
                        "description": desc,
                        "category": "c2_indicator",
                        "file": rel_path,
                        "count": 1,
                    })
            except re.error:
                continue


# ====================================================================
# MODULO: CLASIFICADOR DE ENDPOINTS
# ====================================================================

class EndpointClassifier:
    """Clasifica URLs/IPs extraídas: C2, telemetry, exfiltración, legítima, israelí."""

    @staticmethod
    def classify(secrets_data, decompiled_dir=None):
        urls = secrets_data.get("URL", []) if isinstance(secrets_data, dict) else []
        ips = secrets_data.get("IP_Address", []) if isinstance(secrets_data, dict) else []

        classified = {
            "c2_suspects": [],
            "israeli_endpoints": [],
            "surveillance_endpoints": [],
            "data_exfiltration_suspects": [],
            "suspicious_endpoints": [],
            "legitimate_endpoints": [],
            "tor_i2p_endpoints": [],
            "raw_ip_connections": [],
            "non_standard_ports": [],
            "total_analyzed": 0,
        }

        all_endpoints = []
        for url in urls:
            all_endpoints.append(("url", url))
        for ip in ips:
            all_endpoints.append(("ip", ip))

        classified["total_analyzed"] = len(all_endpoints)

        for etype, endpoint in all_endpoints:
            ep_lower = endpoint.lower()
            categories = EndpointClassifier._categorize(etype, endpoint, ep_lower)
            for cat in categories:
                classified[cat].append({
                    "endpoint": endpoint,
                    "type": etype,
                    "reason": EndpointClassifier._get_reason(cat, ep_lower),
                })

        # Buscar endpoints adicionales en smali (no capturados por SecretsExtractor)
        if decompiled_dir and os.path.isdir(decompiled_dir):
            extra = EndpointClassifier._scan_smali_endpoints(decompiled_dir)
            for cat, items in extra.items():
                if cat in classified:
                    classified[cat].extend(items)

        classified["available"] = True
        classified["risk_summary"] = {
            "c2_count": len(classified["c2_suspects"]),
            "israeli_count": len(classified["israeli_endpoints"]),
            "surveillance_count": len(classified["surveillance_endpoints"]),
            "exfil_count": len(classified["data_exfiltration_suspects"]),
            "tor_count": len(classified["tor_i2p_endpoints"]),
        }
        return classified

    @staticmethod
    def _categorize(etype, endpoint, ep_lower):
        cats = []
        legit = ENDPOINT_CLASSIFICATION["legitimate_domains"]
        suspicious_tlds = ENDPOINT_CLASSIFICATION["suspicious_tlds"]
        c2_ports = ENDPOINT_CLASSIFICATION["c2_ports"]
        vpn_kw = ENDPOINT_CLASSIFICATION["vpn_proxy_keywords"]

        # Check Israeli domains / surveillance keywords
        for tld in ISRAELI_SURVEILLANCE_DOMAINS:
            if tld in ep_lower:
                cats.append("israeli_endpoints")
                break
        for kw in ISRAELI_SURVEILLANCE_KEYWORDS:
            if kw in ep_lower:
                cats.append("surveillance_endpoints")
                break

        # Check TOR/I2P
        if ".onion" in ep_lower or ".i2p" in ep_lower:
            cats.append("tor_i2p_endpoints")

        # Check suspicious TLDs
        for tld in suspicious_tlds:
            if ep_lower.endswith(tld) or tld + "/" in ep_lower or tld + ":" in ep_lower:
                cats.append("suspicious_endpoints")
                break

        # Check non-standard ports
        port_match = re.search(r':(\d{2,5})(?:/|$)', endpoint)
        if port_match:
            port = int(port_match.group(1))
            if port in c2_ports:
                cats.append("c2_suspects")
                cats.append("non_standard_ports")
            elif port not in (80, 443, 8080):
                cats.append("non_standard_ports")

        # Check VPN/proxy keywords
        for kw in vpn_kw:
            if kw in ep_lower:
                cats.append("suspicious_endpoints")
                break

        # Raw IP connections (no domain)
        if etype == "ip":
            cats.append("raw_ip_connections")

        # Check if legitimate
        is_legit = False
        for dom in legit:
            if dom in ep_lower:
                is_legit = True
                break
        if is_legit and not cats:
            cats.append("legitimate_endpoints")
        elif not cats:
            cats.append("suspicious_endpoints")

        return list(set(cats))

    @staticmethod
    def _get_reason(category, ep_lower):
        reasons = {
            "c2_suspects": "Puerto asociado a C2/herramientas de hacking",
            "israeli_endpoints": "Dominio/TLD israelí detectado",
            "surveillance_endpoints": "Keyword de empresa de vigilancia detectada",
            "data_exfiltration_suspects": "Patrón de exfiltración de datos",
            "suspicious_endpoints": "Endpoint no clasificado como legítimo",
            "legitimate_endpoints": "Dominio conocido y legítimo",
            "tor_i2p_endpoints": "Red anónima TOR/I2P",
            "raw_ip_connections": "Conexión directa a IP (sin dominio)",
            "non_standard_ports": "Puerto no estándar",
        }
        return reasons.get(category, "Sin clasificar")

    @staticmethod
    def _scan_smali_endpoints(decompiled_dir):
        """Busca endpoints adicionales en smali que no capturó SecretsExtractor."""
        extra = defaultdict(list)
        ip_port_re = re.compile(
            r'const-string[^"]*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})"'
        )
        raw_domain_re = re.compile(
            r'const-string[^"]*"([a-zA-Z0-9][\w\-]*\.(?:onion|i2p|bit|tk|ml|ga|cf|gq))"'
        )
        for root, _, files in os.walk(decompiled_dir):
            for fname in files:
                if not fname.endswith('.smali'):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    for m in ip_port_re.finditer(content):
                        ip, port = m.group(1), int(m.group(2))
                        if port in ENDPOINT_CLASSIFICATION["c2_ports"]:
                            extra["c2_suspects"].append({
                                "endpoint": f"{ip}:{port}",
                                "type": "ip_port_smali",
                                "reason": f"IP:puerto C2 en smali ({os.path.relpath(fpath, decompiled_dir)})",
                            })
                    for m in raw_domain_re.finditer(content):
                        domain = m.group(1)
                        if ".onion" in domain or ".i2p" in domain:
                            extra["tor_i2p_endpoints"].append({
                                "endpoint": domain,
                                "type": "domain_smali",
                                "reason": f"Dominio TOR/I2P en smali ({os.path.relpath(fpath, decompiled_dir)})",
                            })
                        else:
                            extra["suspicious_endpoints"].append({
                                "endpoint": domain,
                                "type": "domain_smali",
                                "reason": f"Dominio sospechoso en smali ({os.path.relpath(fpath, decompiled_dir)})",
                            })
                except Exception:
                    continue
        return dict(extra)


# ====================================================================
# MODULO: CORRELACION PERMISOS-CODIGO-EXFILTRACION
# ====================================================================

class DataExfiltrationCorrelator:
    """Correlaciona permisos sensibles con código que los usa y destinos de red."""

    @staticmethod
    def correlate(manifest_data, decompiled_dir, secrets_data=None):
        permissions = manifest_data.get("permissions", [])
        chains = []
        permission_usage = []

        # Recopilar todos los archivos smali
        smali_content_cache = {}
        if decompiled_dir and os.path.isdir(decompiled_dir):
            for root, _, files in os.walk(decompiled_dir):
                for fname in files:
                    if fname.endswith('.smali'):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                                smali_content_cache[fpath] = f.read()
                        except Exception:
                            continue

        # Para cada permiso sensible, buscar uso en código
        for perm in permissions:
            perm_info = PERMISSION_DATA_MAP.get(perm)
            if not perm_info:
                continue

            data_type = perm_info["data_type"]
            read_apis = perm_info["read_apis"]
            perm_severity = perm_info["severity"]

            # Buscar archivos que usan las APIs de lectura de este permiso
            files_reading = []
            for fpath, content in smali_content_cache.items():
                for api in read_apis:
                    if api in content:
                        rel = os.path.relpath(fpath, decompiled_dir)
                        files_reading.append({"file": rel, "api": api})
                        break

            if not files_reading:
                permission_usage.append({
                    "permission": perm,
                    "data_type": data_type,
                    "severity": perm_severity,
                    "code_usage_found": False,
                    "exfiltration_risk": "BAJO",
                    "details": "Permiso declarado pero no se encontró código que lo use",
                })
                continue

            # Buscar si los mismos archivos (o cercanos) también usan APIs de red
            files_with_network = []
            for fpath, content in smali_content_cache.items():
                for net_api in NETWORK_EXFIL_APIS:
                    if net_api in content:
                        rel = os.path.relpath(fpath, decompiled_dir)
                        files_with_network.append({"file": rel, "api": net_api})
                        break

            # Buscar si hay archivos que LEEN datos Y envían por red
            reading_files_set = {fr["file"] for fr in files_reading}
            network_files_set = {fn["file"] for fn in files_with_network}
            overlap_files = reading_files_set & network_files_set

            if overlap_files:
                exfil_risk = "CRITICO"
                chain_desc = (f"CADENA DE EXFILTRACION: {data_type} → "
                              f"leído en {len(files_reading)} archivo(s) → "
                              f"enviado por red desde {len(overlap_files)} archivo(s)")
            elif files_with_network:
                exfil_risk = "ALTO"
                chain_desc = (f"RIESGO ALTO: {data_type} leído + red disponible "
                              f"(lectura: {len(files_reading)} archivos, red: {len(files_with_network)} archivos)")
            else:
                exfil_risk = "MEDIO"
                chain_desc = (f"Lectura de {data_type} detectada en "
                              f"{len(files_reading)} archivo(s) sin envío de red evidente")

            chain = {
                "permission": perm,
                "data_type": data_type,
                "severity": perm_severity,
                "exfiltration_risk": exfil_risk,
                "description": chain_desc,
                "reading_code": files_reading[:10],
                "network_code": [f for f in files_with_network if f["file"] in overlap_files][:10],
                "overlap_files": sorted(list(overlap_files))[:10],
            }
            chains.append(chain)

            permission_usage.append({
                "permission": perm,
                "data_type": data_type,
                "severity": perm_severity,
                "code_usage_found": True,
                "exfiltration_risk": exfil_risk,
                "details": chain_desc,
                "files_count": len(files_reading),
            })

        # Buscar endpoints de destino (si se proporcionaron secrets)
        destination_endpoints = []
        if secrets_data and isinstance(secrets_data, dict):
            for url in secrets_data.get("URL", []):
                url_lower = url.lower()
                is_suspicious = True
                for dom in ENDPOINT_CLASSIFICATION["legitimate_domains"]:
                    if dom in url_lower:
                        is_suspicious = False
                        break
                if is_suspicious:
                    destination_endpoints.append(url)

        # Calcular resumen
        critico_chains = [c for c in chains if c["exfiltration_risk"] == "CRITICO"]
        alto_chains = [c for c in chains if c["exfiltration_risk"] == "ALTO"]

        return {
            "available": True,
            "exfiltration_chains": chains,
            "permission_usage": permission_usage,
            "destination_endpoints": destination_endpoints[:50],
            "summary": {
                "total_permissions_analyzed": len([p for p in permissions if p in PERMISSION_DATA_MAP]),
                "permissions_with_code": len([pu for pu in permission_usage if pu.get("code_usage_found")]),
                "critical_chains": len(critico_chains),
                "high_risk_chains": len(alto_chains),
                "data_types_at_risk": list(set(c["data_type"] for c in chains if c["exfiltration_risk"] in ("CRITICO", "ALTO"))),
            },
        }


# ====================================================================
# MODULO: JADX - DECOMPILACION JAVA Y ANALISIS PROFUNDO
# ====================================================================

class JadxDecompiler:
    """
    Decompilador Java basado en jadx, con aislamiento de subprocess,
    límite de heap JVM y análisis streaming del código Java resultante.

    Diseño:
      - jadx se ejecuta como binario externo (NUNCA como lib in-process).
      - JAVA_TOOL_OPTIONS limita el heap de la JVM antes de que arranque.
      - El análisis del output es streaming por archivo: nunca se carga
        todo el árbol en memoria.
      - Si jadx no está en PATH, retorna {"available": False} sin crashear.
    """

    PATTERNS = {
        "runtime_exec": re.compile(
            r'Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(',
            re.IGNORECASE
        ),
        "process_builder": re.compile(
            r'\bnew\s+ProcessBuilder\s*\(',
            re.IGNORECASE
        ),
        "class_forname": re.compile(
            r'Class\.forName\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        ),
        "method_invoke": re.compile(
            r'\.getDeclaredMethod\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        ),
        "dex_classloader": re.compile(
            r'\b(?:Dex|Path|InMemory|Base)?ClassLoader\s*\(',
        ),
        "load_library": re.compile(
            r'System\.(?:loadLibrary|load)\s*\(\s*["\']([^"\']+)["\']',
        ),
        "cipher_instance": re.compile(
            r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ),
        "secret_key_spec": re.compile(
            r'new\s+SecretKeySpec\s*\(',
        ),
        "iv_param_spec": re.compile(
            r'new\s+IvParameterSpec\s*\(',
        ),
        "trust_all_certs": re.compile(
            r'public\s+void\s+checkServerTrusted[^{]*\{\s*\}',
            re.MULTILINE
        ),
        "hostname_verifier_true": re.compile(
            r'public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;',
            re.MULTILINE
        ),
        "object_input_stream": re.compile(
            r'ObjectInputStream\s*\([^)]*\)\.readObject\s*\(',
        ),
        "webview_js_interface": re.compile(
            r'\.addJavascriptInterface\s*\(',
        ),
        "webview_js_enabled": re.compile(
            r'\.setJavaScriptEnabled\s*\(\s*true\s*\)',
        ),
        "webview_file_access": re.compile(
            r'\.setAllowFileAccess(?:FromFileURLs|FromURLs)?\s*\(\s*true\s*\)',
        ),
        "url_http": re.compile(
            r'["\'](https?://[^\s"\']{6,256})["\']'
        ),
        "ip_hardcoded": re.compile(
            r'["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?)["\']'
        ),
        "shared_prefs_write": re.compile(
            r'\.putString\s*\(\s*["\'](?:password|token|api_key|secret|jwt|auth)',
            re.IGNORECASE
        ),
        "root_check": re.compile(
            r'["\'](?:/system/xbin/su|/system/bin/su|/sbin/su|'
            r'com\.noshufou\.android\.su|com\.thirdparty\.superuser|'
            r'eu\.chainfire\.supersu|com\.topjohnwu\.magisk)["\']'
        ),
        "debug_check": re.compile(
            r'ApplicationInfo\.FLAG_DEBUGGABLE|'
            r'android\.os\.Debug\.isDebuggerConnected'
        ),
        "hook_detection": re.compile(
            r'["\'](?:frida|xposed|substrate|epic\.hook|'
            r'de\.robv\.android\.xposed|re\.frida\.server)["\']',
            re.IGNORECASE
        ),
    }

    EXCLUDE_PATH_FRAGMENTS = (
        'androidx/', 'com/google/android/gms/', 'com/google/firebase/',
        'kotlin/', 'kotlinx/', 'com/google/common/',
        'org/jetbrains/', 'com/squareup/', 'com/bumptech/glide/',
        'io/reactivex/', 'retrofit2/', 'okhttp3/', 'okio/',
    )

    MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB

    @staticmethod
    def analyze(apk_path, report_dir):
        jadx_bin = shutil.which('jadx')
        if not jadx_bin:
            return {
                "available": False,
                "error": "jadx no encontrado en PATH. Instalar con: "
                         "https://github.com/skylot/jadx/releases"
            }

        out_dir = os.path.join(report_dir, "jadx_output")
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as e:
            return {"available": False, "error": f"No se pudo crear out_dir: {e}"}

        decompile_result = JadxDecompiler._run_jadx(jadx_bin, apk_path, out_dir)
        if not decompile_result["ok"]:
            return {
                "available": False,
                "error": decompile_result.get("error", "jadx falló"),
                "jadx_stderr": decompile_result.get("stderr", "")[:1000],
            }

        findings = JadxDecompiler._analyze_decompiled(out_dir)

        return {
            "available": True,
            "output_dir": out_dir,
            "java_files_count": findings["files_scanned"],
            "java_files_skipped": findings["files_skipped"],
            "total_size_bytes": findings["total_bytes"],
            "findings_by_category": findings["by_category"],
            "findings_count": findings["total_findings"],
            "top_findings": findings["top_findings"],
            "suspicious_classes": findings["suspicious_classes"],
            "hardcoded_urls": findings["hardcoded_urls"][:50],
            "hardcoded_ips": findings["hardcoded_ips"][:30],
            "reflection_targets": findings["reflection_targets"][:30],
            "native_libs_loaded": findings["native_libs"],
            "crypto_algorithms_used": findings["crypto_algos"],
            "loaded_classes_via_reflection": findings["loaded_classes"][:30],
            "high_risk_indicators": JadxDecompiler._score_risk(findings),
            "jadx_warnings": decompile_result.get("warnings", "")[:500],
        }

    @staticmethod
    def _run_jadx(jadx_bin, apk_path, out_dir, heap_mb=2048, timeout=360):
        env = os.environ.copy()
        existing_opts = env.get('JAVA_TOOL_OPTIONS', '')
        env['JAVA_TOOL_OPTIONS'] = (
            f'{existing_opts} -Xmx{heap_mb}m -XX:+ExitOnOutOfMemoryError '
            f'-XX:+UseG1GC'
        ).strip()

        cmd = [
            jadx_bin,
            '-d', out_dir,
            '--no-res',
            '--no-debug-info',
            '--log-level', 'ERROR',
            '-j', '2',
            '--show-bad-code',
            '--respect-bytecode-access-modifiers',
            apk_path,
        ]

        try:
            proc = subprocess.run(
                cmd, env=env, capture_output=True,
                timeout=timeout, check=False,
            )
            has_output = (
                os.path.isdir(out_dir) and any(os.scandir(out_dir))
            )
            if has_output:
                return {
                    "ok": True,
                    "exit_code": proc.returncode,
                    "warnings": proc.stderr.decode('utf-8', errors='replace'),
                }
            else:
                return {
                    "ok": False,
                    "error": f"jadx no produjo output (exit={proc.returncode})",
                    "stderr": proc.stderr.decode('utf-8', errors='replace'),
                }
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"jadx timeout tras {timeout}s"}
        except FileNotFoundError:
            return {"ok": False, "error": f"jadx no ejecutable: {jadx_bin}"}
        except Exception as e:
            return {"ok": False, "error": f"jadx excepcion: {type(e).__name__}: {e}"}

    @staticmethod
    def _analyze_decompiled(out_dir):
        state = {
            "files_scanned": 0,
            "files_skipped": 0,
            "total_bytes": 0,
            "by_category": {k: 0 for k in JadxDecompiler.PATTERNS},
            "total_findings": 0,
            "top_findings": [],
            "suspicious_classes": [],
            "hardcoded_urls": [],
            "hardcoded_ips": [],
            "reflection_targets": [],
            "native_libs": [],
            "crypto_algos": [],
            "loaded_classes": [],
        }

        seen_urls = set()
        seen_ips = set()
        seen_reflection = set()
        seen_libs = set()
        seen_crypto = set()
        seen_loaded = set()

        for root, dirs, files in os.walk(out_dir):
            dirs[:] = [d for d in dirs if not any(
                os.path.join(root, d).replace(out_dir, '').lstrip('/\\').startswith(frag.rstrip('/'))
                for frag in JadxDecompiler.EXCLUDE_PATH_FRAGMENTS
            )]

            for fname in files:
                if not fname.endswith('.java'):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, out_dir).replace('\\', '/')
                if any(frag in rel_path for frag in JadxDecompiler.EXCLUDE_PATH_FRAGMENTS):
                    state["files_skipped"] += 1
                    continue

                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    state["files_skipped"] += 1
                    continue

                if size > JadxDecompiler.MAX_FILE_SIZE_BYTES:
                    state["files_skipped"] += 1
                    continue

                state["total_bytes"] += size
                state["files_scanned"] += 1

                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                        content = fh.read()
                except (OSError, IOError):
                    state["files_skipped"] += 1
                    state["files_scanned"] -= 1
                    continue

                file_hits = 0

                for cat, pattern in JadxDecompiler.PATTERNS.items():
                    matches = pattern.findall(content)
                    if not matches:
                        continue

                    state["by_category"][cat] += len(matches)
                    file_hits += len(matches)

                    if cat == "url_http":
                        for m in matches:
                            if m not in seen_urls and len(seen_urls) < 200:
                                seen_urls.add(m)
                                state["hardcoded_urls"].append(m)
                    elif cat == "ip_hardcoded":
                        for m in matches:
                            if m not in seen_ips and len(seen_ips) < 100:
                                seen_ips.add(m)
                                state["hardcoded_ips"].append(m)
                    elif cat == "class_forname":
                        for m in matches:
                            if m not in seen_loaded and len(seen_loaded) < 100:
                                seen_loaded.add(m)
                                state["loaded_classes"].append(m)
                    elif cat == "method_invoke":
                        for m in matches:
                            if m not in seen_reflection and len(seen_reflection) < 100:
                                seen_reflection.add(m)
                                state["reflection_targets"].append(m)
                    elif cat == "load_library":
                        for m in matches:
                            if m not in seen_libs:
                                seen_libs.add(m)
                                state["native_libs"].append(m)
                    elif cat == "cipher_instance":
                        for m in matches:
                            if m not in seen_crypto:
                                seen_crypto.add(m)
                                state["crypto_algos"].append(m)

                state["total_findings"] += file_hits

                if file_hits >= 3:
                    state["suspicious_classes"].append({
                        "class": rel_path,
                        "hits": file_hits,
                        "size_bytes": size,
                    })

                if file_hits >= 5 and len(state["top_findings"]) < 50:
                    state["top_findings"].append({
                        "file": rel_path,
                        "hits": file_hits,
                    })

        state["suspicious_classes"].sort(key=lambda x: x["hits"], reverse=True)
        state["suspicious_classes"] = state["suspicious_classes"][:30]
        state["top_findings"].sort(key=lambda x: x["hits"], reverse=True)

        return state

    @staticmethod
    def _score_risk(findings):
        indicators = []
        cats = findings["by_category"]

        if cats.get("trust_all_certs", 0) > 0:
            indicators.append({
                "type": "TLS_BYPASS", "severity": "CRITICO",
                "description": "TrustManager.checkServerTrusted vacio detectado: permite MITM al aceptar cualquier certificado.",
                "occurrences": cats["trust_all_certs"],
            })

        if cats.get("hostname_verifier_true", 0) > 0:
            indicators.append({
                "type": "TLS_HOSTNAME_BYPASS", "severity": "CRITICO",
                "description": "HostnameVerifier.verify retorna true sin validar: desactiva verificacion de hostname en SSL.",
                "occurrences": cats["hostname_verifier_true"],
            })

        if cats.get("webview_js_interface", 0) > 0 and cats.get("webview_js_enabled", 0) > 0:
            indicators.append({
                "type": "WEBVIEW_RCE_RISK", "severity": "ALTO",
                "description": "WebView con JavaScript habilitado + addJavascriptInterface: riesgo de RCE si el contenido no es de confianza.",
                "occurrences": cats["webview_js_interface"],
            })

        if cats.get("object_input_stream", 0) > 0:
            indicators.append({
                "type": "INSECURE_DESERIALIZATION", "severity": "ALTO",
                "description": "ObjectInputStream.readObject detectado: vulnerable a deserializacion maliciosa si la fuente no es confiable.",
                "occurrences": cats["object_input_stream"],
            })

        if cats.get("dex_classloader", 0) > 0:
            indicators.append({
                "type": "DYNAMIC_CODE_LOADING", "severity": "ALTO",
                "description": "DexClassLoader/PathClassLoader detectado: la app carga codigo en tiempo de ejecucion (payload dropping clasico).",
                "occurrences": cats["dex_classloader"],
            })

        if cats.get("runtime_exec", 0) > 0 or cats.get("process_builder", 0) > 0:
            total = cats.get("runtime_exec", 0) + cats.get("process_builder", 0)
            indicators.append({
                "type": "COMMAND_EXECUTION", "severity": "MEDIO",
                "description": "Runtime.exec/ProcessBuilder detectado: la app ejecuta comandos del sistema. Verificar origen de argumentos.",
                "occurrences": total,
            })

        refl_total = cats.get("class_forname", 0) + cats.get("method_invoke", 0)
        if refl_total >= 20:
            indicators.append({
                "type": "HEAVY_REFLECTION", "severity": "MEDIO",
                "description": f"Uso intensivo de reflection ({refl_total} sitios): patron comun en ofuscacion y evasion de analisis estatico.",
                "occurrences": refl_total,
            })

        if cats.get("hook_detection", 0) > 0:
            indicators.append({
                "type": "ANTI_HOOKING", "severity": "INFO",
                "description": "Deteccion de Frida/Xposed/Substrate en el codigo: la app intenta protegerse contra hooking dinamico.",
                "occurrences": cats["hook_detection"],
            })

        if cats.get("root_check", 0) > 0:
            indicators.append({
                "type": "ROOT_DETECTION", "severity": "INFO",
                "description": "Rutinas de deteccion de root detectadas: la app valida integridad del dispositivo.",
                "occurrences": cats["root_check"],
            })

        if cats.get("shared_prefs_write", 0) > 0:
            indicators.append({
                "type": "SENSITIVE_PREFS", "severity": "MEDIO",
                "description": "Escritura de campos sensibles (password/token/api_key) en SharedPreferences sin cifrar detectada.",
                "occurrences": cats["shared_prefs_write"],
            })

        return indicators


# ====================================================================
# MOTOR PRINCIPAL
# ====================================================================

class ApkilisEngine:
    def __init__(self, target_file):
        self.target = target_file
        self.ext = Path(target_file).suffix.lower().lstrip('.')
        self.app_name = Path(target_file).stem
        self.report_dir = None
        self.base_apk = target_file
        self.decompiled_dir = None
        self.data = {}

    def _preflight_check(self):
        """Validate environment: check for required/optional external tools."""
        checks = {
            "apktool": {"required": True, "cmd": ["apktool", "--version"]},
            "jarsigner": {"required": False, "cmd": ["jarsigner", "-help"]},
            "keytool": {"required": False, "cmd": ["keytool", "-help"]},
            "apkid": {"required": False, "cmd": ["apkid", "--version"]},
            "jadx": {"required": False, "cmd": ["jadx", "--version"]},
        }
        python_libs = {
            "androguard": HAS_ANDROGUARD,
            "quark-engine": HAS_QUARK,
            "quark-lowlevel": HAS_QUARK_LOWLEVEL,
            "yara-python": HAS_YARA,
            "lief": HAS_LIEF,
            "cryptography": HAS_CRYPTOGRAPHY,
            "rich": HAS_RICH,
            "jinja2": HAS_JINJA,
            "lxml": HAS_LXML,
            "androwarn": HAS_ANDROWARN,
            "ssdeep": HAS_SSDEEP,
            "tlsh": HAS_TLSH,
        }

        tool_status = {}
        for tool, info in checks.items():
            try:
                subprocess.run(info["cmd"], capture_output=True, timeout=10)
                tool_status[tool] = True
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                tool_status[tool] = False


        # Log and display
        logger.info("=== PRE-FLIGHT CHECK ===")
        if HAS_RICH:
            t = Table(title="Pre-flight Environment Check", box=box.ROUNDED, border_style="cyan")
            t.add_column("Componente", style="white")
            t.add_column("Tipo", style="dim")
            t.add_column("Estado", justify="center")
            for tool, found in sorted(tool_status.items()):
                req = checks.get(tool, {}).get("required", False)
                tipo = "[bold]Requerido[/bold]" if req else "Opcional"
                status = "[green]✓[/green]" if found else ("[red]✗ FALTA[/red]" if req else "[yellow]—[/yellow]")
                t.add_row(tool, tipo, status)
            for lib, found in sorted(python_libs.items()):
                status = "[green]✓[/green]" if found else "[yellow]—[/yellow]"
                t.add_row(lib, "Python lib", status)
            console.print(t)
            console.print()
        else:
            print("\n  [Pre-flight Check]")
            for tool, found in sorted(tool_status.items()):
                marker = "OK" if found else "FALTA"
                print(f"    {tool}: {marker}")
            for lib, found in sorted(python_libs.items()):
                marker = "OK" if found else "No disponible"
                print(f"    {lib}: {marker}")
            print()

        for tool, found in tool_status.items():
            logger.info(f"  Tool {tool}: {'OK' if found else 'NOT FOUND'}")
        for lib, found in python_libs.items():
            logger.info(f"  Lib {lib}: {'OK' if found else 'NOT FOUND'}")

        # Fail hard if required tool is missing
        for tool, info in checks.items():
            if info["required"] and not tool_status.get(tool, False):
                raise RuntimeError(f"Herramienta requerida no encontrada: {tool}. Instálela antes de continuar.")


    def run(self):
        date_str = datetime.now().strftime("%d%m%Y_%H%M%S")
        dir_name = f"APKILIS_{self.app_name}_{date_str}"
        self.report_dir = os.path.join(get_desktop_path(), dir_name)
        os.makedirs(self.report_dir, exist_ok=True)
        extract_dir = os.path.join(self.report_dir, "extracted_bundle")
        self.decompiled_dir = os.path.join(self.report_dir, "decompiled")

        # Pre-flight environment validation
        self._preflight_check()

        steps = [
            ("Calculando hashes (cadena de custodia)", self._step_hashes),
            ("Extrayendo bundle", self._step_extract_bundle),
            ("Decompilando con apktool", self._step_decompile),
            ("Analizando certificado de firma", self._step_certificate),
            ("Analizando AndroidManifest.xml", self._step_manifest),
            ("Analizando seguridad de red", self._step_network),
            ("Detectando trackers y SDKs", self._step_trackers),
            ("Analizando codigo Smali", self._step_smali),
            ("Extrayendo secretos hardcodeados", self._step_secrets),
            ("Analizando estructura del APK", self._step_structure),
            ("Androguard: analisis profundo DEX", self._step_androguard),
            ("Quark-Engine: deteccion heuristica malware", self._step_quark),
            ("Enjarify: conversion DEX a JAR", self._step_enjarify),
            ("Jadx: decompilacion Java y analisis profundo", self._step_jadx),
            ("YARA: escaneo de reglas y firmas", self._step_yara),
            ("APKiD: deteccion de packers/ofuscadores", self._step_apkid),
            ("LIEF: analisis de librerias nativas", self._step_lief),
            ("Endpoints: extraccion de URLs y APIs", self._step_endpoints),
            ("Inyeccion: deteccion de vulnerabilidades", self._step_injection),
            ("Certificado: analisis profundo X.509", self._step_crypto_cert),
            ("Forense: bases de datos y keystore", self._step_forensic_db),
            ("Detectando frameworks (Flutter/RN/Unity/UE)", self._step_framework),
            ("Analisis de seguridad bancaria/alto valor", self._step_banking),
            ("Analisis anti-cheat de juegos", self._step_anticheat),
            ("Generando kit de analisis dinamico", self._step_dynamic_analysis),
            ("Deobfuscacion de strings", self._step_string_deobfuscation),
            ("Verificacion de esquemas de firma", self._step_signature_scheme),
            ("Analisis profundo de recursos", self._step_deep_resources),
            ("Deteccion de abuso accesibilidad/overlay", self._step_accessibility_overlay),
            ("Superficie de ataque Intent/IPC", self._step_intent_ipc),
            ("Deteccion de backdoors y C2", self._step_backdoor_c2),
            ("Clasificacion de endpoints", self._step_endpoint_classifier),
            ("Correlacion permisos-codigo-exfiltracion", self._step_exfiltration_correlator),
            ("Androwarn: analisis de comportamientos", self._step_androwarn),
            ("Fuzzy hashing: ssdeep + TLSH", self._step_fuzzy_hash),
            ("Entropia y deteccion de ofuscacion", self._step_entropy_obfuscation),
            ("MITRE ATT&CK: mapeo de tecnicas", self._step_mitre_attack),
            ("Timeline forense: cronologia de eventos", self._step_forensic_timeline),
            ("OWASP Mobile Top 10: evaluacion automatica", self._step_owasp),
            ("Calculando puntuacion de riesgo", self._step_risk),
            ("Generando reportes", self._step_reports),
        ]

        if HAS_RICH:
            import time as _time
            step_times = []
            with Progress(
                SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                BarColumn(), TextColumn("[bold green]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(), TextColumn("⏱"), TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Analisis forense...", total=len(steps))
                for step_idx, (desc, func) in enumerate(steps):
                    progress.update(task, description=desc)
                    t0 = _time.monotonic()
                    step_ok = True
                    try:
                        logger.info(f"Iniciando: {desc}")
                        func(extract_dir)
                        logger.info(f"Completado: {desc}")
                    except (StepTimeout, MemoryError) as e:
                        logger.error(f"CRITICO en '{desc}': {type(e).__name__}: {e}")
                        step_ok = False
                    except Exception as e:
                        logger.error(f"Error en '{desc}': {e}", exc_info=True)
                        step_ok = False
                    elapsed = _time.monotonic() - t0
                    step_times.append((desc, elapsed, step_ok))
                    progress.advance(task)

            # Tabla resumen de tiempos por módulo
            time_table = Table(title="⏱ Tiempos por Módulo", box=box.ROUNDED, border_style="bright_blue")
            time_table.add_column("#", style="dim", width=3)
            time_table.add_column("Módulo", style="cyan", max_width=55)
            time_table.add_column("Tiempo", style="white", justify="right")
            time_table.add_column("Estado", justify="center")
            total_time = 0.0
            for idx, (sdesc, stime, sok) in enumerate(step_times, 1):
                total_time += stime
                if stime > 30:
                    t_color = "red"
                elif stime > 10:
                    t_color = "yellow"
                else:
                    t_color = "green"
                status_str = "[green]✓ OK[/green]" if sok else "[red]✗ ERROR[/red]"
                time_table.add_row(str(idx), sdesc, f"[{t_color}]{stime:.1f}s[/{t_color}]", status_str)
            time_table.add_row("", "[bold]TOTAL[/bold]", f"[bold]{total_time:.1f}s[/bold]", "")
            console.print(time_table)
            self.data["_step_times"] = step_times
        else:
            for i, (desc, func) in enumerate(steps, 1):
                print(f"  [{i}/{len(steps)}] {desc}...")
                try:
                    logger.info(f"Iniciando: {desc}")
                    func(extract_dir)
                    logger.info(f"Completado: {desc}")
                except (StepTimeout, MemoryError) as e:
                    logger.error(f"CRITICO en '{desc}': {type(e).__name__}: {e}")
                    print(f"    [!] {type(e).__name__}: {e}")
                except Exception as e:
                    logger.error(f"Error en '{desc}': {e}", exc_info=True)
                    print(f"    [!] Error: {e}")

        return self.data, self.report_dir

    def _step_hashes(self, _):
        self.data["hashes"] = compute_hashes(self.target)
        self.data["file_info"] = file_metadata(self.target)

    def _step_extract_bundle(self, extract_dir):
        if self.ext in ('apks', 'apkm', 'xapk'):
            os.makedirs(extract_dir, exist_ok=True)
            base, splits, meta = BundleExtractor.extract(self.target, extract_dir)
            if base:
                self.base_apk = base
                self.data["bundle"] = {
                    "base_apk": os.path.basename(base),
                    "split_apks": [os.path.basename(s) for s in splits],
                    "bundle_meta": meta,
                    "inventory": BundleExtractor.inventory(extract_dir),
                }
            else:
                raise RuntimeError("No se encontro APK base en el bundle")
        else:
            self.data["bundle"] = None

    def _step_decompile(self, _):
        try:
            subprocess.run(
                ['apktool', 'd', '-f', self.base_apk, '-o', self.decompiled_dir],
                check=True, capture_output=True, timeout=300)
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode(errors='replace')[:200] if e.stderr else "desconocido"
            logger.warning(f"apktool fallo: {err_msg}")
            # Fallback: create decompiled dir and extract AndroidManifest.xml from APK
            os.makedirs(self.decompiled_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(self.base_apk, 'r') as zf:
                    for name in zf.namelist():
                        if name == 'AndroidManifest.xml' or name.endswith('.smali'):
                            continue  # binary manifest won't help, smali needs apktool
                        if name.startswith('res/') or name.startswith('assets/'):
                            zf.extract(name, self.decompiled_dir)
            except Exception:
                pass
            logger.info("apktool fallo pero se continua con extraccion parcial del APK")
        except FileNotFoundError:
            os.makedirs(self.decompiled_dir, exist_ok=True)
            logger.warning("apktool no encontrado, continuando con directorio vacio")

    def _step_certificate(self, _):
        self.data["certificate"] = CertAnalyzer.analyze(self.base_apk)

    def _step_manifest(self, _):
        self.data["manifest"] = ManifestAnalyzer.analyze(self.decompiled_dir)

    def _step_network(self, _):
        self.data["network_security"] = NetworkSecurityAnalyzer.analyze(self.decompiled_dir)

    def _step_trackers(self, _):
        self.data["trackers"] = TrackerDetector.detect(self.decompiled_dir)

    def _step_smali(self, _):
        self.data["smali_analysis"] = SmaliAnalyzer.analyze(self.decompiled_dir)

    def _step_secrets(self, _):
        secrets, count = SecretsExtractor.extract(self.decompiled_dir)
        self.data["secrets"] = secrets
        self.data["secrets_files_scanned"] = count

    def _step_structure(self, _):
        self.data["structure"] = StructureAnalyzer.analyze(self.base_apk, self.decompiled_dir)

    def _step_androguard(self, _):
        try:
            self.data["androguard"] = run_with_timeout(
                AndroguardAnalyzer.analyze, args=(self.base_apk,), timeout_sec=180)
        except StepTimeout:
            logger.warning("Androguard timeout (180s) - análisis DEX omitido")
            self.data["androguard"] = {"available": False, "error": "Timeout: AnalyzeAPK excedió 180s"}
        except MemoryError:
            logger.error("Androguard MemoryError - APK demasiado grande para análisis DEX")
            self.data["androguard"] = {"available": False, "error": "MemoryError: APK demasiado grande"}

    def _step_quark(self, _):
        try:
            self.data["quark"] = run_in_subprocess_with_memlimit(
                QuarkAnalyzer.analyze, args=(self.base_apk,),
                kwargs={"max_rules": 50}, timeout_sec=90, mem_limit_mb=2560)
        except StepTimeout:
            logger.warning("Quark-Engine timeout (90s)")
            self.data["quark"] = {"available": False, "error": "Timeout: Quark excedió 90s"}
        except MemoryError:
            logger.error("Quark-Engine MemoryError (subprocess killed)")
            self.data["quark"] = {"available": False, "error": "MemoryError: proceso hijo excedió límite de RAM"}
        except RuntimeError as e:
            logger.error(f"Quark-Engine subprocess error: {e}")
            self.data["quark"] = {"available": False, "error": f"Error subprocess: {e}"}

    def _step_enjarify(self, _):
        jar_dir = os.path.join(self.report_dir, "jar_output")
        os.makedirs(jar_dir, exist_ok=True)
        self.data["enjarify"] = EnjarifyConverter.convert(self.base_apk, jar_dir)

    def _step_jadx(self, _):
        try:
            self.data["jadx"] = run_in_subprocess_with_memlimit(
                JadxDecompiler.analyze,
                args=(self.base_apk, self.report_dir),
                timeout_sec=420, mem_limit_mb=3072)
        except StepTimeout:
            logger.warning("Jadx timeout (420s) - decompilacion Java omitida")
            self.data["jadx"] = {"available": False, "error": "Timeout: jadx excedio 420s"}
        except MemoryError:
            logger.error("Jadx MemoryError - APK demasiado grande")
            self.data["jadx"] = {"available": False, "error": "MemoryError: proceso hijo excedio RAM"}
        except (RuntimeError, Exception) as e:
            logger.error(f"Jadx error: {e}")
            self.data["jadx"] = {"available": False, "error": str(e)}

    def _step_yara(self, _):
        self.data["yara"] = YaraScanner.scan(self.base_apk, self.decompiled_dir)

    def _step_apkid(self, _):
        self.data["apkid"] = APKiDAnalyzer.analyze(self.base_apk)

    def _step_lief(self, _):
        self.data["lief"] = LIEFAnalyzer.analyze(self.base_apk)

    def _step_endpoints(self, _):
        self.data["endpoints"] = EndpointExtractor.analyze(self.decompiled_dir)

    def _step_injection(self, _):
        self.data["injection"] = InjectionAnalyzer.analyze(
            self.decompiled_dir, self.data.get("manifest", {}))

    def _step_crypto_cert(self, _):
        self.data["crypto_cert"] = CryptoCertAnalyzer.analyze(self.base_apk)

    def _step_dynamic_analysis(self, _):
        self.data["dynamic_analysis"] = DynamicAnalysisGenerator.generate(
            self.base_apk, self.data.get("manifest", {}),
            self.report_dir, self.data.get("structure"))

    def _step_string_deobfuscation(self, _):
        self.data["string_deobfuscation"] = StringDeobfuscator.analyze(self.decompiled_dir)

    def _step_signature_scheme(self, _):
        self.data["signature_scheme"] = SignatureSchemeChecker.analyze(self.base_apk, self.decompiled_dir)

    def _step_deep_resources(self, _):
        self.data["deep_resources"] = DeepResourceAnalyzer.analyze(self.base_apk, self.decompiled_dir)

    def _step_accessibility_overlay(self, _):
        self.data["accessibility_overlay"] = AccessibilityOverlayAnalyzer.analyze(
            self.data.get("manifest", {}), self.decompiled_dir)

    def _step_intent_ipc(self, _):
        self.data["intent_ipc"] = IntentIPCAnalyzer.analyze(
            self.data.get("manifest", {}), self.decompiled_dir)

    def _step_forensic_db(self, _):
        self.data["forensic_db"] = ForensicDBExtractor.analyze(
            self.base_apk, self.decompiled_dir, self.data.get("structure"))

    def _step_framework(self, _):
        self.data["framework"] = FrameworkAnalyzer.analyze(
            self.base_apk, self.data.get("structure"), self.decompiled_dir)

    def _step_banking(self, _):
        self.data["banking"] = BankingSecurityAnalyzer.analyze(
            self.base_apk, self.data.get("manifest"), self.decompiled_dir,
            self.data.get("structure"))

    def _step_anticheat(self, _):
        self.data["anticheat"] = GameAntiCheatAnalyzer.analyze(
            self.base_apk, self.data.get("structure"), self.decompiled_dir)

    def _step_backdoor_c2(self, _):
        self.data["backdoor_c2"] = BackdoorC2Detector.analyze(self.decompiled_dir)

    def _step_endpoint_classifier(self, _):
        self.data["endpoint_classification"] = EndpointClassifier.classify(
            self.data.get("secrets", {}), self.decompiled_dir)

    def _step_exfiltration_correlator(self, _):
        self.data["exfiltration"] = DataExfiltrationCorrelator.correlate(
            self.data.get("manifest", {}), self.decompiled_dir,
            self.data.get("secrets"))

    def _step_androwarn(self, _):
        try:
            self.data["androwarn"] = run_in_subprocess_with_memlimit(
                AndrowarnAnalyzer.analyze, args=(self.base_apk,),
                timeout_sec=120, mem_limit_mb=2048)
        except StepTimeout:
            logger.warning("Androwarn timeout (120s)")
            self.data["androwarn"] = {"available": False, "error": "Timeout: Androwarn excedió 120s"}
        except (MemoryError, RuntimeError) as e:
            logger.error(f"Androwarn error: {e}")
            self.data["androwarn"] = {"available": False, "error": str(e)}

    def _step_fuzzy_hash(self, _):
        self.data["fuzzy_hashes"] = FuzzyHasher.analyze(self.base_apk)

    def _step_entropy_obfuscation(self, _):
        self.data["entropy_obfuscation"] = EntropyObfuscationAnalyzer.analyze(self.base_apk)

    def _step_mitre_attack(self, _):
        self.data["mitre_attack"] = MitreAttackMobile.analyze(self.data)

    def _step_forensic_timeline(self, _):
        self.data["forensic_timeline"] = ForensicTimeline.analyze(self.base_apk, self.data)

    def _step_owasp(self, _):
        self.data["owasp_mobile"] = OWASPMobileTop10Analyzer.analyze(self.data)

    def _step_risk(self, _):
        self.data["risk"] = RiskScorer.calculate(
            self.data.get("manifest", {}), self.data.get("certificate", {}),
            self.data.get("network_security", {}), self.data.get("secrets", {}),
            self.data.get("smali_analysis", {}), self.data.get("structure", {}),
            androguard=self.data.get("androguard"),
            quark=self.data.get("quark"),
            yara_results=self.data.get("yara"),
            apkid=self.data.get("apkid"),
            lief_results=self.data.get("lief"),
            endpoints=self.data.get("endpoints"),
            injection=self.data.get("injection"),
            crypto_cert=self.data.get("crypto_cert"),
            forensic_db=self.data.get("forensic_db"),
            framework=self.data.get("framework"),
            banking=self.data.get("banking"),
            anticheat=self.data.get("anticheat"),
            androwarn=self.data.get("androwarn"),
            entropy_obfuscation=self.data.get("entropy_obfuscation"),
            mitre=self.data.get("mitre_attack"),
            timeline=self.data.get("forensic_timeline"),
            backdoor_c2=self.data.get("backdoor_c2"),
            endpoint_classification=self.data.get("endpoint_classification"),
            exfiltration=self.data.get("exfiltration"),
            string_deobfuscation=self.data.get("string_deobfuscation"),
            signature_scheme=self.data.get("signature_scheme"),
            deep_resources=self.data.get("deep_resources"),
            accessibility_overlay=self.data.get("accessibility_overlay"),
            intent_ipc=self.data.get("intent_ipc"),
            owasp_mobile=self.data.get("owasp_mobile"))

    def _step_reports(self, _):
        md, js, ht = ReportGenerator.generate_all(self.report_dir, self.target, self.data)
        self.data["reports"] = {"markdown": md, "json": js, "html": ht}


# ====================================================================
# INTERFAZ CYBERPUNK DASHBOARD
# ====================================================================

def _cyberpunk_bar(value, max_val, width=20, fill_char="█", empty_char="░"):
    """Genera una barra de progreso estilo cyberpunk."""
    if max_val <= 0:
        return empty_char * width
    filled = int((value / max_val) * width)
    filled = min(filled, width)
    return fill_char * filled + empty_char * (width - filled)


def display_cyberpunk_dashboard(data, report_dir, step_times=None):
    """Interfaz cyberpunk con 6 paneles neon para resultados del análisis forense."""
    if not HAS_RICH:
        return False

    from datetime import datetime

    risk = data.get("risk", {})
    manifest = data.get("manifest", {})
    trackers = data.get("trackers", {})
    secrets = data.get("secrets", {})
    ag = data.get("androguard", {})
    quark = data.get("quark", {})
    yara_r = data.get("yara", {})
    apkid = data.get("apkid", {})
    lief_r = data.get("lief", {})
    endpoints = data.get("endpoints", {})
    injection = data.get("injection", {})
    owasp = data.get("owasp_mobile", {})
    banking = data.get("banking_security", {})
    crypto_cert = data.get("crypto_cert", {})
    structure = data.get("structure", {})
    smali = data.get("smali_analysis", {})
    enjarify = data.get("enjarify", {})
    jadx = data.get("jadx", {})
    bc2 = data.get("backdoor_c2", {})
    mitre = data.get("mitre_attack", {})
    total_secrets = sum(len(v) for v in secrets.values()) if isinstance(secrets, dict) else 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score = risk.get("score", 0)
    level = risk.get("level", "N/A")

    # ── Colores neon ──
    NEON_PINK = "bright_magenta"
    NEON_CYAN = "bright_cyan"
    NEON_GREEN = "green"
    NEON_RED = "bright_red"
    NEON_YELLOW = "yellow"

    # ════════════════════════════════════════════════════════════════
    # PANEL 6 — BARRA SUPERIOR: Título + hora + versión
    # ════════════════════════════════════════════════════════════════
    header_text = Text(justify="center")
    header_text.append("╔══════════════════════════════════════════════════════════════════════════════════════════╗\n", style=f"bold {NEON_PINK}")
    header_text.append("║  ", style=f"bold {NEON_PINK}")
    header_text.append("r/dPixls", style=f"bold {NEON_PINK} underline")
    header_text.append(" — ", style=f"bold {NEON_CYAN}")
    header_text.append("P U N I X", style=f"bold {NEON_CYAN}")
    header_text.append(f"   ⏰ {now}", style=f"{NEON_GREEN}")
    header_text.append(f"   v{VERSION}", style=f"bold {NEON_YELLOW}")
    header_text.append("  ║\n", style=f"bold {NEON_PINK}")
    header_text.append("║  ", style=f"bold {NEON_PINK}")
    header_text.append("▀▄▀▄▀▄ ", style=f"bold {NEON_CYAN}")
    header_text.append("APKILIS FORENSIC CYBER DASHBOARD", style=f"bold {NEON_PINK}")
    header_text.append(" ▄▀▄▀▄▀", style=f"bold {NEON_CYAN}")
    header_text.append("  ║\n", style=f"bold {NEON_PINK}")
    header_text.append("╚══════════════════════════════════════════════════════════════════════════════════════════╝", style=f"bold {NEON_PINK}")

    console.print(header_text)
    console.print()

    # ════════════════════════════════════════════════════════════════
    # PANEL 1 — CONSOLE: Logs en vivo del análisis
    # ════════════════════════════════════════════════════════════════
    console_lines = []
    if step_times:
        for desc, elapsed, ok in step_times:
            if ok:
                status = f"[{NEON_GREEN}]✓[/{NEON_GREEN}]"
            else:
                status = f"[{NEON_RED}]✗[/{NEON_RED}]"
            if elapsed > 30:
                t_style = NEON_RED
            elif elapsed > 10:
                t_style = NEON_YELLOW
            else:
                t_style = NEON_CYAN
            short_desc = desc[:38] + "…" if len(desc) > 39 else desc
            console_lines.append(f" [{NEON_CYAN}]>[/{NEON_CYAN}] {status} [{t_style}]{elapsed:5.1f}s[/{t_style}] {short_desc}")
    else:
        console_lines.append(f"  [{NEON_CYAN}]>[/{NEON_CYAN}] Análisis completado")
        console_lines.append(f"  [{NEON_CYAN}]>[/{NEON_CYAN}] {len(risk.get('findings', []))} hallazgos detectados")
        console_lines.append(f"  [{NEON_CYAN}]>[/{NEON_CYAN}] Reportes generados en {report_dir}")

    # Limitar a las últimas 18 líneas
    if len(console_lines) > 18:
        console_lines = console_lines[-18:]

    console_text = "\n".join(console_lines)
    panel_console = Panel(
        console_text,
        title=f"[bold {NEON_CYAN}]◈ CONSOLE ◈[/bold {NEON_CYAN}]",
        border_style=NEON_CYAN,
        box=box.DOUBLE,
        padding=(0, 1),
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 2 — POWER / METADATA: Info básica del APK
    # ════════════════════════════════════════════════════════════════
    pkg = manifest.get("package", "N/A")
    ver_name = manifest.get("version_name", "?")
    ver_code = manifest.get("version_code", "?")
    min_sdk = manifest.get("min_sdk", "?")
    target_sdk = manifest.get("target_sdk", "?")
    file_info = data.get("file_info", {})
    file_size = file_info.get("size_bytes", 0)
    if file_size > 1048576:
        size_str = f"{file_size / 1048576:.1f} MB"
    elif file_size > 1024:
        size_str = f"{file_size / 1024:.1f} KB"
    else:
        size_str = f"{file_size} B"
    sig_scheme = data.get("signature_scheme", {})
    sig_str = "N/A"
    if sig_scheme.get("available"):
        schemes = sig_scheme.get("schemes", {})
        sig_str = " ".join(f"{k}={'✓' if v else '✗'}" for k, v in schemes.items())

    hashes = data.get("hashes", {})
    sha256_short = hashes.get("sha256", "N/A")[:16] + "…" if hashes.get("sha256") else "N/A"

    meta_table = Table(show_header=False, box=None, padding=(0, 1))
    meta_table.add_column("K", style=f"bold {NEON_PINK}", width=12)
    meta_table.add_column("V", style="white")
    meta_table.add_row("📦 Paquete", f"[bold white]{pkg}[/bold white]")
    meta_table.add_row("📋 Versión", f"{ver_name} (code: {ver_code})")
    meta_table.add_row("🎯 SDK", f"min={min_sdk} target={target_sdk}")
    meta_table.add_row("📏 Tamaño", f"[bold {NEON_CYAN}]{size_str}[/bold {NEON_CYAN}]")
    meta_table.add_row("🔏 Firma", sig_str)
    meta_table.add_row("🔑 SHA256", sha256_short)

    n_perms = len(manifest.get("permissions", []))
    n_danger = len(manifest.get("dangerous_permission_details", []))
    n_exported = len(manifest.get("exported_components", []))
    n_activities = manifest.get("activity_count", "?")
    meta_table.add_row("🛡️ Permisos", f"{n_perms} ({n_danger} [bold {NEON_RED}]peligrosos[/bold {NEON_RED}])")
    meta_table.add_row("📤 Export.", f"{n_exported} componentes")

    panel_meta = Panel(
        meta_table,
        title=f"[bold {NEON_PINK}]◈ POWER / METADATA ◈[/bold {NEON_PINK}]",
        border_style=NEON_PINK,
        box=box.DOUBLE,
        padding=(0, 1),
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 3 — PROCESSES: Tabla de módulos con estado
    # ════════════════════════════════════════════════════════════════
    proc_table = Table(box=box.SIMPLE_HEAVY, border_style=NEON_CYAN, padding=(0, 1))
    proc_table.add_column("Módulo", style=f"bold {NEON_CYAN}", width=22)
    proc_table.add_column("Estado", justify="center", width=7)
    proc_table.add_column("Hallazgos", justify="right", width=10)

    modules_status = [
        ("Androguard", ag.get("available", False), f"{ag.get('class_count', 0)} clases" if ag.get("available") else "—"),
        ("Quark-Engine", quark.get("available", False), quark.get("threat_level", "—") if quark.get("available") else "—"),
        ("YARA Scanner", yara_r.get("available", False), f"{len(yara_r.get('matches', []))} match" if yara_r.get("available") else "—"),
        ("APKiD", apkid.get("available", False), f"{len(apkid.get('packers', []))}P {len(apkid.get('obfuscators', []))}O" if apkid.get("available") else "—"),
        ("LIEF (ELF)", lief_r.get("available", False), f"{lief_r.get('total_libs', 0)} libs" if lief_r.get("available") else "—"),
        ("Endpoints", endpoints.get("available", False), f"{endpoints.get('total_endpoints', 0)}" if endpoints.get("available") else "—"),
        ("Inyección", injection.get("available", False), f"{injection.get('total_vulnerabilities', 0)}" if injection.get("available") else "—"),
        ("OWASP Top10", owasp.get("available", False), f"{owasp.get('total_findings', 0)}" if owasp.get("available") else "—"),
        ("Banking Sec.", banking.get("available", False), f"{banking.get('total_findings', 0)}" if banking.get("available") else "—"),
        ("Crypto/Cert", crypto_cert.get("available", False), f"{len(crypto_cert.get('vulnerabilities', []))}" if crypto_cert.get("available") else "—"),
        ("Backdoor/C2", bc2.get("available", False), f"{bc2.get('total_findings', 0)}" if bc2.get("available") else "—"),
        ("MITRE ATT&CK", mitre.get("available", False), f"{mitre.get('total_techniques', 0)} tech" if mitre.get("available") else "—"),
        ("Enjarify", enjarify.get("available", False), f"{enjarify.get('class_count', 0)} cls" if enjarify.get("available") else "—"),
        ("Jadx", jadx.get("available", False), f"{jadx.get('java_files_count', 0)} java, {jadx.get('findings_count', 0)} hits" if jadx.get("available") else "—"),
        ("Smali", bool(smali), f"{smali.get('total_classes', 0)} cls" if smali else "—"),
    ]

    for mod_name, available, detail in modules_status:
        if available:
            st = f"[bold {NEON_GREEN}] ✔ ON [/bold {NEON_GREEN}]"
        else:
            st = f"[dim] ✗ OFF[/dim]"
        proc_table.add_row(mod_name, st, detail)

    panel_proc = Panel(
        proc_table,
        title=f"[bold {NEON_CYAN}]◈ PROCESSES ◈[/bold {NEON_CYAN}]",
        border_style=NEON_CYAN,
        box=box.DOUBLE,
        padding=(0, 0),
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 4 — SCORECARD: Puntuación + barras OWASP
    # ════════════════════════════════════════════════════════════════
    if score >= 75:
        score_color = NEON_RED
        score_label = "CRITICO"
    elif score >= 50:
        score_color = NEON_YELLOW
        score_label = "ALTO"
    elif score >= 25:
        score_color = "bright_yellow"
        score_label = "MEDIO"
    else:
        score_color = NEON_GREEN
        score_label = "BAJO"

    score_lines = []
    score_lines.append(f"  [bold {score_color}]╔═══════════════════════════╗[/bold {score_color}]")
    score_lines.append(f"  [bold {score_color}]║   RIESGO: {score:3d} / 100       ║[/bold {score_color}]")
    score_lines.append(f"  [bold {score_color}]║   NIVEL:  {score_label:<17s}║[/bold {score_color}]")
    score_lines.append(f"  [bold {score_color}]╚═══════════════════════════╝[/bold {score_color}]")
    score_lines.append("")

    # Barras OWASP Mobile Top 10
    owasp_cats = owasp.get("categories", [])
    if owasp_cats:
        score_lines.append(f"  [bold {NEON_PINK}]── OWASP Mobile Top 10 ──[/bold {NEON_PINK}]")
        sev_colors_map = {"CRITICO": NEON_RED, "ALTO": NEON_YELLOW, "MEDIO": "bright_yellow", "BAJO": NEON_GREEN}
        for cat in owasp_cats:
            cat_id = cat.get("id", "M?")
            cat_score = cat.get("score", 0)
            cat_sev = cat.get("severity", "BAJO")
            bar_color = sev_colors_map.get(cat_sev, "white")
            bar = _cyberpunk_bar(cat_score, 100, width=12)
            short_name = cat.get("name", "?")[:16]
            score_lines.append(f"  [{bar_color}]{cat_id:<3s}{bar} {cat_score:3d}[/{bar_color}] {short_name}")
    else:
        score_lines.append(f"  [{NEON_CYAN}]OWASP: Sin datos[/{NEON_CYAN}]")

    panel_score = Panel(
        "\n".join(score_lines),
        title=f"[bold {NEON_PINK}]◈ SCORECARD ◈[/bold {NEON_PINK}]",
        border_style=NEON_PINK,
        box=box.DOUBLE,
        padding=(0, 1),
    )

    # ════════════════════════════════════════════════════════════════
    # PANEL 5 — STATUS: Indicadores rápidos
    # ════════════════════════════════════════════════════════════════
    def _indicator(label, value, is_bad=None):
        """Genera una línea de indicador con ícono."""
        if is_bad is None:
            is_bad = bool(value)
        if is_bad:
            return f"  [bold {NEON_RED}]❌[/bold {NEON_RED}] {label}: [bold {NEON_RED}]{value}[/bold {NEON_RED}]"
        else:
            return f"  [bold {NEON_GREEN}]✅[/bold {NEON_GREEN}] {label}: [bold {NEON_GREEN}]{value}[/bold {NEON_GREEN}]"

    status_lines = []

    # Secretos
    status_lines.append(_indicator("Secretos hardcoded", total_secrets, total_secrets > 0))

    # Permisos peligrosos
    status_lines.append(_indicator("Permisos peligrosos", n_danger, n_danger > 3))

    # Libs nativas sospechosas
    n_dangerous_imports = len(lief_r.get("dangerous_imports_found", [])) if lief_r.get("available") else 0
    status_lines.append(_indicator("Imports nativos peligr.", n_dangerous_imports, n_dangerous_imports > 0))

    # Trackers
    n_trackers = trackers.get("total", 0)
    status_lines.append(_indicator("Trackers detectados", n_trackers, n_trackers > 3))

    # Backdoor indicators
    has_backdoor = bc2.get("has_backdoor_indicators", False) if bc2.get("available") else False
    status_lines.append(_indicator("Backdoor/C2", "SÍ" if has_backdoor else "NO", has_backdoor))

    # Injection vulns
    n_inj = injection.get("total_vulnerabilities", 0) if injection.get("available") else 0
    status_lines.append(_indicator("Vulns. inyección", n_inj, n_inj > 0))

    # Exportados sin proteger
    status_lines.append(_indicator("Componentes export.", n_exported, n_exported > 5))

    # Packed/obfuscated
    eo = data.get("entropy_obfuscation", {})
    obf_score = eo.get("obfuscation_score", 0)
    status_lines.append(_indicator("Ofuscación score", f"{obf_score}/100", obf_score > 50))

    # YARA matches
    n_yara = len(yara_r.get("matches", []))
    status_lines.append(_indicator("YARA coincidencias", n_yara, n_yara > 0))

    # Jadx findings
    n_jadx = jadx.get("findings_count", 0)
    n_jadx_risk = len(jadx.get("high_risk_indicators", []))
    status_lines.append(_indicator("Jadx hallazgos", f"{n_jadx} ({n_jadx_risk} riesgo)", n_jadx_risk > 0))

    # Findings por severidad
    findings = risk.get("findings", [])
    n_critico = sum(1 for s, _ in findings if s == "CRITICO")
    n_alto = sum(1 for s, _ in findings if s == "ALTO")
    sev_line = f"  [bold {NEON_PINK}]── Severidades ──[/bold {NEON_PINK}]"
    status_lines.append(sev_line)
    status_lines.append(f"  [bold {NEON_RED}]🔴 CRITICO: {n_critico}[/bold {NEON_RED}]  [{NEON_YELLOW}]🟠 ALTO: {n_alto}[/{NEON_YELLOW}]")
    n_medio = sum(1 for s, _ in findings if s == "MEDIO")
    n_bajo = sum(1 for s, _ in findings if s == "BAJO")
    status_lines.append(f"  [bright_yellow]🟡 MEDIO: {n_medio}[/bright_yellow]  [{NEON_GREEN}]🟢 BAJO: {n_bajo}[/{NEON_GREEN}]")

    panel_status = Panel(
        "\n".join(status_lines),
        title=f"[bold {NEON_YELLOW}]◈ STATUS ◈[/bold {NEON_YELLOW}]",
        border_style=NEON_YELLOW,
        box=box.DOUBLE,
        padding=(0, 1),
    )

    # ════════════════════════════════════════════════════════════════
    # LAYOUT: Composición de los 6 paneles
    # ════════════════════════════════════════════════════════════════
    # Usamos Layout de Rich para organizar los paneles
    layout = Layout()

    layout.split_column(
        Layout(name="top_row", size=3),
        Layout(name="middle"),
        Layout(name="bottom"),
    )

    # Top row is implicit (header already printed above)

    layout["middle"].split_row(
        Layout(panel_console, name="console", ratio=2),
        Layout(name="center_right", ratio=3),
    )

    layout["center_right"].split_row(
        Layout(panel_meta, name="meta", ratio=1),
        Layout(panel_score, name="scorecard", ratio=1),
    )

    layout["bottom"].split_row(
        Layout(panel_proc, name="processes", ratio=2),
        Layout(panel_status, name="status", ratio=1),
    )

    # Ajustar tamaños
    layout["top_row"].visible = False  # header ya impreso arriba
    layout["middle"].size = None
    layout["bottom"].size = None

    console.print(layout)

    # ── Línea separadora neon ──
    console.print(f"[bold {NEON_PINK}]{'━' * console.width}[/bold {NEON_PINK}]")

    # ── Reportes generados ──
    reports_text = (
        f"  [{NEON_CYAN}]📄[/{NEON_CYAN}] Markdown: REPORTE_FORENSE.md\n"
        f"  [{NEON_CYAN}]🌐[/{NEON_CYAN}] HTML:     REPORTE_FORENSE.html\n"
        f"  [{NEON_CYAN}]📊[/{NEON_CYAN}] JSON:     resultado.json\n"
        f"  [{NEON_CYAN}]📁[/{NEON_CYAN}] Dir:      {report_dir}"
    )
    console.print(Panel(
        reports_text,
        title=f"[bold {NEON_GREEN}]◈ REPORTES GENERADOS ◈[/bold {NEON_GREEN}]",
        border_style=NEON_GREEN,
        box=box.DOUBLE,
    ))

    return True


# ====================================================================
# INTERFAZ CLI
# ====================================================================

def display_results(data, report_dir):
    # Intentar mostrar dashboard cyberpunk primero
    step_times = data.get("_step_times")
    try:
        if display_cyberpunk_dashboard(data, report_dir, step_times=step_times):
            return
    except Exception as e:
        logger.warning(f"Dashboard cyberpunk falló, usando vista clásica: {e}")

    risk = data.get("risk", {})
    manifest = data.get("manifest", {})
    trackers = data.get("trackers", {})
    secrets = data.get("secrets", {})
    smali = data.get("smali_analysis", {})
    structure = data.get("structure", {})
    ag = data.get("androguard", {})
    quark = data.get("quark", {})
    enjarify = data.get("enjarify", {})
    yara_r = data.get("yara", {})
    apkid = data.get("apkid", {})
    lief_r = data.get("lief", {})
    crypto_cert = data.get("crypto_cert", {})
    dynamic = data.get("dynamic_analysis", {})
    total_secrets = sum(len(v) for v in secrets.values()) if isinstance(secrets, dict) else 0

    if HAS_RICH:
        console.print()
        rc = {"CRITICO":"red","ALTO":"yellow","MEDIO":"bright_yellow","BAJO":"green"}.get(risk.get("level",""),"white")
        console.print(Panel(
            f"[bold {rc}]{risk.get('level_icon','')} PUNTUACION: {risk.get('score',0)}/100 - {risk.get('level','N/A')}[/bold {rc}]",
            title="[bold]VEREDICTO DE RIESGO[/bold]", border_style=rc, padding=(1,4)))

        stats = Table(box=box.ROUNDED, show_header=False, border_style="bright_blue")
        stats.add_column("Metrica", style="cyan")
        stats.add_column("Valor", style="white")
        stats.add_row("Paquete", manifest.get("package","N/A"))
        stats.add_row("Permisos", str(len(manifest.get("permissions",[]))))
        stats.add_row("Peligrosos", str(len(manifest.get("dangerous_permission_details",[]))))
        stats.add_row("Exportados", str(len(manifest.get("exported_components",[]))))
        stats.add_row("Trackers", str(trackers.get("total",0)))
        stats.add_row("Secretos", str(total_secrets))
        stats.add_row("Hallazgos codigo", str(len(smali.get("grouped",{}))))
        stats.add_row("Archivos DEX", str(len(structure.get("dex_files",[]))))
        stats.add_row("Libs nativas", str(len(structure.get("native_libs",[]))))
        console.print(stats)

        # Androguard stats
        if ag.get("available"):
            ag_table = Table(title="Androguard - Analisis DEX", box=box.SIMPLE, border_style="magenta")
            ag_table.add_column("Metrica", style="magenta")
            ag_table.add_column("Valor", style="white")
            ag_table.add_row("Clases", str(ag.get("class_count", 0)))
            ag_table.add_row("Metodos", str(ag.get("method_count", 0)))
            ag_table.add_row("APIs peligrosas", str(len(ag.get("dangerous_api_calls", []))))
            ag_table.add_row("Strings interesantes", str(len(ag.get("interesting_strings", []))))
            ag_table.add_row("Librerias", str(len(ag.get("libraries_detected", []))))
            console.print(ag_table)

        # Quark stats
        if quark.get("available"):
            q_color = {"CRITICO":"red","ALTO":"yellow","MEDIO":"bright_yellow","BAJO":"green","LIMPIO":"green"}.get(quark.get("threat_level",""),"white")
            q_panel = (
                f"[bold {q_color}]Amenaza: {quark.get('threat_level','N/A')}[/bold {q_color}] | "
                f"Reglas escaneadas: {quark.get('rules_scanned',0)} | "
                f"Coincidencias: {len(quark.get('rules_matched',[]))} | "
                f"Clasificacion: {quark.get('classification',{}).get('label','N/A')}"
            )
            behaviors = quark.get("behaviors_detected", [])
            if behaviors:
                q_panel += f"\nComportamientos: " + ", ".join(f"{b['behavior']}({b['count']})" for b in behaviors[:6])
            console.print(Panel(q_panel, title="[bold]Quark-Engine - Heuristica Malware[/bold]", border_style=q_color))

        # Enjarify stats
        if enjarify.get("available"):
            console.print(f"  [green]Enjarify:[/green] JAR generado con {enjarify.get('class_count',0)} clases ({enjarify.get('method','')}) -> {os.path.basename(enjarify.get('jar_path',''))}")

        # Jadx stats
        jadx = data.get("jadx", {})
        if jadx.get("available"):
            n_risks = len(jadx.get("high_risk_indicators", []))
            jadx_color = "red" if n_risks > 0 else "green"
            console.print(f"  [{jadx_color}]Jadx:[/{jadx_color}] {jadx.get('java_files_count',0)} archivos Java, "
                          f"{jadx.get('findings_count',0)} hallazgos, "
                          f"{n_risks} indicadores riesgo")

        # YARA stats
        if yara_r.get("available"):
            ym = yara_r.get("matches", [])
            yara_color = "red" if any(m.get("severity") == "CRITICO" for m in ym) else ("yellow" if ym else "green")
            y_panel = (
                f"[bold {yara_color}]Coincidencias: {len(ym)}[/bold {yara_color}] | "
                f"Reglas cargadas: {yara_r.get('rules_loaded',0)} | "
                f"Archivos escaneados: {yara_r.get('files_scanned',0)}"
            )
            if ym:
                y_panel += f"\nDetecciones: " + ", ".join(m['rule'] for m in ym[:6])
            console.print(Panel(y_panel, title="[bold]YARA - Motor de Reglas[/bold]", border_style=yara_color))

        # APKiD stats
        if apkid.get("available"):
            apkid_items = []
            if apkid.get("packers"): apkid_items.append(f"[red]{len(apkid['packers'])} packers[/red]")
            if apkid.get("obfuscators"): apkid_items.append(f"[yellow]{len(apkid['obfuscators'])} ofuscadores[/yellow]")
            if apkid.get("protectors"): apkid_items.append(f"[yellow]{len(apkid['protectors'])} protectores[/yellow]")
            if apkid.get("anti_analysis"): apkid_items.append(f"[red]{len(apkid['anti_analysis'])} anti-análisis[/red]")
            if apkid.get("compilers"): apkid_items.append(f"[dim]{len(apkid['compilers'])} compiladores[/dim]")
            if apkid_items:
                console.print(f"  [magenta]APKiD:[/magenta] " + " | ".join(apkid_items))

        # LIEF stats
        if lief_r.get("available"):
            lief_dangerous = lief_r.get("dangerous_imports_found", [])
            lief_color = "red" if any(i.get("severity") == "CRITICO" for i in lief_dangerous) else ("yellow" if lief_dangerous else "green")
            l_panel = (
                f"[bold {lief_color}]Libs: {lief_r.get('total_libs',0)}[/bold {lief_color}] | "
                f"Imports peligrosos: {len(lief_dangerous)} | "
                f"Libs sospechosas: {len(lief_r.get('suspicious_libs',[]))}"
            )
            if lief_r.get("has_debug_symbols"):
                l_panel += " | [yellow]Símbolos de debug encontrados[/yellow]"
            console.print(Panel(l_panel, title="[bold]LIEF - Análisis Nativo ELF[/bold]", border_style=lief_color))

        # Endpoints stats
        ep_r = data.get("endpoints", {})
        if ep_r.get("available") and ep_r.get("total_endpoints", 0) > 0:
            ep_by = ep_r.get("endpoints_by_type", {})
            n_ips = len(ep_by.get("internal_ips", []))
            n_cloud = len(ep_by.get("cloud_resources", []))
            n_auth = len(ep_by.get("auth_endpoints", []))
            ep_color = "red" if n_ips else ("yellow" if (n_cloud or n_auth) else "cyan")
            ep_text = (
                f"[bold {ep_color}]Total: {ep_r['total_endpoints']}[/bold {ep_color}] | "
                f"IPs internas: {n_ips} | Cloud: {n_cloud} | Auth: {n_auth} | "
                f"APIs: {len(ep_by.get('api_endpoints',[]))} | Deep links: {len(ep_by.get('deep_links',[]))}"
            )
            console.print(Panel(ep_text, title="[bold]Endpoints - URLs y APIs[/bold]", border_style=ep_color))

        # Injection stats
        inj_r = data.get("injection", {})
        if inj_r.get("available") and inj_r.get("total_vulnerabilities", 0) > 0:
            n_crit = len(inj_r.get("by_severity", {}).get("CRITICO", []))
            n_alto = len(inj_r.get("by_severity", {}).get("ALTO", []))
            n_med = len(inj_r.get("by_severity", {}).get("MEDIO", []))
            inj_color = "red" if n_crit else ("yellow" if n_alto else "bright_yellow")
            inj_text = (
                f"[bold {inj_color}]Total: {inj_r['total_vulnerabilities']}[/bold {inj_color}] | "
                f"Críticos: {n_crit} | Altos: {n_alto} | Medios: {n_med}"
            )
            if inj_r.get("exported_attack_surface"):
                inj_text += f" | [red]Exportados vuln: {len(inj_r['exported_attack_surface'])}[/red]"
            console.print(Panel(inj_text, title="[bold]Inyección - Vulnerabilidades[/bold]", border_style=inj_color))

        # Certificado profundo
        if crypto_cert.get("available"):
            anomalies = crypto_cert.get("cert_anomalies", [])
            cc_color = "red" if anomalies else "green"
            cc_text = f"Certificados: {len(crypto_cert.get('certificates',[]))} | Anomalías: {len(anomalies)}"
            if anomalies:
                cc_text += f"\n" + "\n".join(f"  ⚠ {a}" for a in anomalies[:4])
            console.print(Panel(cc_text, title="[bold]Certificado X.509 (cryptography)[/bold]", border_style=cc_color))

        # Dynamic Analysis stats
        if dynamic.get("available"):
            frida_count = len(dynamic.get("frida_scripts", {}))
            adb_count = sum(len(c.get("commands",[])) for c in dynamic.get("adb_commands",[]))
            drozer_count = sum(len(c.get("commands",[])) for c in dynamic.get("drozer_commands",[]))
            hooks_count = len(dynamic.get("runtime_hooks", []))
            d_panel = (
                f"[bold green]🔬 Kit Dinámico Generado[/bold green]\n"
                f"  Frida Scripts: {frida_count} | ADB Commands: {adb_count}\n"
                f"  Drozer Modules: {drozer_count} | Runtime Hooks: {hooks_count}\n"
                f"  📁 Carpeta: dynamic_analysis/"
            )
            console.print(Panel(d_panel, title="[bold]Análisis Dinámico[/bold]", border_style="green"))

        # Framework detection
        fw_data = data.get("framework", {})
        if fw_data.get("available") and fw_data.get("detected_frameworks"):
            fw_lines = "[bold magenta]🔧 Frameworks Detectados[/bold magenta]\n"
            for fw in fw_data["detected_frameworks"]:
                fw_lines += f"  • {fw.get('name','')} (Confianza: {fw.get('confidence','?')}"
                if fw.get("version"):
                    fw_lines += f", v{fw['version']}"
                fw_lines += ")\n"
            if fw_data.get("primary_framework"):
                fw_lines += f"  🎯 Principal: {fw_data['primary_framework']}"
            console.print(Panel(fw_lines.rstrip(), title="[bold]Frameworks[/bold]", border_style="magenta"))

        # Forensic DB
        fdb = data.get("forensic_db", {})
        if fdb.get("available"):
            n_db = len(fdb.get("databases", []))
            n_ks = len(fdb.get("keystore_usage", []))
            n_pin = len(fdb.get("cert_pinning_analysis", []))
            fdb_text = (
                f"[bold cyan]🔬 Análisis Forense Profundo[/bold cyan]\n"
                f"  Bases de datos: {n_db} | Keystore refs: {n_ks} | Cert pinning: {n_pin}"
            )
            console.print(Panel(fdb_text, title="[bold]Forense DB/Crypto[/bold]", border_style="cyan"))

        # Banking security
        bank = data.get("banking", {})
        if bank.get("available"):
            n_se = len(bank.get("secure_element", []))
            n_bio = len(bank.get("biometric_analysis", []))
            n_tok = len(bank.get("token_extraction", []))
            n_at = len(bank.get("anti_tampering", []))
            b_color = {"Critical":"red","High":"yellow","Medium":"bright_yellow"}.get(bank.get("risk_level",""),"green")
            bank_text = (
                f"[bold {b_color}]🏦 Seguridad Bancaria/Alto Valor[/bold {b_color}]\n"
                f"  SecureElement: {n_se} | Biometric: {n_bio} | Tokens: {n_tok} | Anti-tamper: {n_at}\n"
                f"  Nivel de riesgo: {bank.get('risk_level', 'N/A')}"
            )
            console.print(Panel(bank_text, title="[bold]Banking Security[/bold]", border_style=b_color))

        # Anti-cheat
        ac = data.get("anticheat", {})
        if ac.get("available") and ac.get("anticheat_systems"):
            ac_names = ", ".join(s.get("name","") for s in ac["anticheat_systems"][:5])
            n_mem = len(ac.get("memory_protections", []))
            ac_text = (
                f"[bold red]🎮 Anti-Cheat Detectado[/bold red]\n"
                f"  Sistemas: {ac_names}\n"
                f"  Memory protections: {n_mem} | Exploit surfaces: {len(ac.get('exploit_surfaces',[]))}"
            )
            console.print(Panel(ac_text, title="[bold]Game Anti-Cheat[/bold]", border_style="red"))

        # Androwarn
        aw_data = data.get("androwarn", {})
        if aw_data.get("available"):
            aw_color = {"CRITICO":"red","ALTO":"yellow","MEDIO":"bright_yellow","BAJO":"green","LIMPIO":"green"}.get(aw_data.get("severity",""),"white")
            aw_cats = list(aw_data.get("behaviors", {}).keys())
            aw_text = (
                f"[bold {aw_color}]Severidad: {aw_data.get('severity','N/A')}[/bold {aw_color}] | "
                f"Comportamientos: {aw_data.get('total_behaviors',0)} | "
                f"Categorías: {len(aw_cats)}"
            )
            if aw_cats:
                aw_text += f"\n  {', '.join(c.replace('_',' ').title() for c in aw_cats[:5])}"
            console.print(Panel(aw_text, title="[bold]Androwarn - Comportamientos[/bold]", border_style=aw_color))

        # Fuzzy Hashing
        fh_data = data.get("fuzzy_hashes", {})
        if fh_data.get("available"):
            apk_h = fh_data.get("apk_hashes", {})
            fh_parts = []
            if apk_h.get("ssdeep"):
                fh_parts.append(f"ssdeep: `{apk_h['ssdeep'][:50]}...`")
            if apk_h.get("tlsh"):
                fh_parts.append(f"TLSH: `{str(apk_h['tlsh'])[:50]}...`")
            n_dex = len(fh_data.get("dex_hashes", []))
            fh_text = " | ".join(fh_parts) + f"\n  DEX hashes: {n_dex}"
            console.print(Panel(fh_text, title="[bold]Fuzzy Hashing[/bold]", border_style="bright_blue"))

        # Entropy + Obfuscation
        eo_data = data.get("entropy_obfuscation", {})
        if eo_data.get("available"):
            obf_s = eo_data.get("obfuscation_score", 0)
            eo_color = "red" if obf_s >= 60 else ("yellow" if obf_s >= 30 else "green")
            eo_text = (
                f"[bold {eo_color}]Entropía media: {eo_data.get('overall_entropy',0):.2f}[/bold {eo_color}] | "
                f"Packed: {len(eo_data.get('packed_files',[]))} | "
                f"Ofuscación: {obf_s}/100"
            )
            inds = eo_data.get("obfuscation_indicators", [])
            if inds:
                eo_text += "\n  " + "\n  ".join(f"⚠ {i}" for i in inds[:3])
            console.print(Panel(eo_text, title="[bold]Entropía y Ofuscación[/bold]", border_style=eo_color))

        # Backdoor / C2 Detection
        bc2 = data.get("backdoor_c2", {})
        if bc2.get("available") and bc2.get("total_findings", 0) > 0:
            bc2_color = "red" if bc2.get("has_backdoor_indicators") else ("yellow" if bc2.get("has_spyware_indicators") else "bright_yellow")
            bc2_text = (
                f"[bold {bc2_color}]🚨 {bc2.get('total_findings', 0)} indicadores detectados[/bold {bc2_color}]\n"
                f"  Backdoor/C2: {'SÍ' if bc2.get('has_backdoor_indicators') else 'No'} | "
                f"Spyware: {'SÍ' if bc2.get('has_spyware_indicators') else 'No'} | "
                f"Exfiltración: {'SÍ' if bc2.get('has_exfiltration') else 'No'}"
            )
            cats = bc2.get("by_category", {})
            if cats:
                bc2_text += "\n  Categorías: " + ", ".join(f"{k}({len(v)})" for k, v in sorted(cats.items(), key=lambda x: -len(x[1]))[:6])
            console.print(Panel(bc2_text, title="[bold]Backdoor / C2 Detection[/bold]", border_style=bc2_color))

        # Endpoint Classification
        epc = data.get("endpoint_classification", {})
        if epc.get("available"):
            rs = epc.get("risk_summary", {})
            epc_color = "red" if (rs.get("c2_count", 0) + rs.get("surveillance_count", 0)) > 0 else ("yellow" if rs.get("israeli_count", 0) > 0 else "green")
            epc_text = (
                f"[bold {epc_color}]📡 Endpoints analizados: {epc.get('total_analyzed', 0)}[/bold {epc_color}]\n"
                f"  C2 sospechosos: {rs.get('c2_count', 0)} | "
                f"Israelíes: {rs.get('israeli_count', 0)} | "
                f"Vigilancia: {rs.get('surveillance_count', 0)} | "
                f"TOR/I2P: {rs.get('tor_count', 0)} | "
                f"Exfiltración: {rs.get('exfil_count', 0)}"
            )
            if epc.get("surveillance_endpoints"):
                epc_text += "\n  ⚠ Vigilancia: " + ", ".join(e["endpoint"][:50] for e in epc["surveillance_endpoints"][:3])
            if epc.get("c2_suspects"):
                epc_text += "\n  ⚠ C2: " + ", ".join(e["endpoint"][:50] for e in epc["c2_suspects"][:3])
            console.print(Panel(epc_text, title="[bold]Clasificación de Endpoints[/bold]", border_style=epc_color))

        # Data Exfiltration Correlation
        exf = data.get("exfiltration", {})
        if exf.get("available"):
            ex_sum = exf.get("summary", {})
            crit_c = ex_sum.get("critical_chains", 0)
            high_c = ex_sum.get("high_risk_chains", 0)
            exf_color = "red" if crit_c > 0 else ("yellow" if high_c > 0 else "green")
            exf_text = (
                f"[bold {exf_color}]🔗 Permisos analizados: {ex_sum.get('total_permissions_analyzed', 0)} | "
                f"Con código: {ex_sum.get('permissions_with_code', 0)}[/bold {exf_color}]\n"
                f"  Cadenas CRITICAS: {crit_c} | Alto riesgo: {high_c}"
            )
            risk_types = ex_sum.get("data_types_at_risk", [])
            if risk_types:
                exf_text += f"\n  Datos en riesgo: {', '.join(risk_types)}"
            for chain in exf.get("exfiltration_chains", [])[:3]:
                if chain["exfiltration_risk"] in ("CRITICO", "ALTO"):
                    exf_text += f"\n  ⚠ {chain['description'][:100]}"
            console.print(Panel(exf_text, title="[bold]Correlación Permisos↔Código↔Exfiltración[/bold]", border_style=exf_color))

        # MITRE ATT&CK
        mitre_data = data.get("mitre_attack", {})
        if mitre_data.get("available") and mitre_data.get("techniques"):
            n_tech = mitre_data.get("total_techniques", 0)
            tactics = mitre_data.get("coverage_summary", {})
            mitre_text = (
                f"[bold cyan]🎯 {n_tech} técnicas mapeadas[/bold cyan]\n"
            )
            if tactics:
                mitre_text += "  " + " | ".join(f"{t}: {c}" for t, c in sorted(tactics.items(), key=lambda x: -x[1])[:6])
            console.print(Panel(mitre_text, title="[bold]MITRE ATT&CK for Mobile[/bold]", border_style="cyan"))

        # Forensic Timeline
        tl_data = data.get("forensic_timeline", {})
        if tl_data.get("available"):
            tr = tl_data.get("time_range", {})
            n_inc = len(tl_data.get("inconsistencies", []))
            tl_color = "red" if n_inc > 0 else "green"
            tl_text = (
                f"[bold {tl_color}]📅 {tr.get('total_events',0)} eventos[/bold {tl_color}] | "
                f"Rango: {tr.get('earliest','N/A')} — {tr.get('latest','N/A')} | "
                f"Inconsistencias: {n_inc}"
            )
            for inc in tl_data.get("inconsistencies", [])[:3]:
                tl_text += f"\n  ⚠ {inc.get('description','')[:80]}"
            console.print(Panel(tl_text, title="[bold]Timeline Forense[/bold]", border_style=tl_color))

        # String Deobfuscation
        sd_data = data.get("string_deobfuscation", {})
        if sd_data.get("available") and sd_data.get("total_decoded", 0) > 0:
            sd_int = len(sd_data.get("interesting_strings", []))
            sd_crit = len(sd_data.get("by_severity", {}).get("CRITICO", []))
            sd_color = "red" if sd_crit else ("yellow" if sd_int else "green")
            console.print(f"  [{sd_color}]Deobfusc:[/{sd_color}] {sd_data.get('total_decoded',0)} strings decodificadas, {sd_int} interesantes ({sd_crit} críticas)")

        # Signature Scheme
        sig_data = data.get("signature_scheme", {})
        if sig_data.get("available"):
            sig_vulns = len(sig_data.get("vulnerabilities", []))
            sig_color = "red" if sig_data.get("janus_vulnerable") else ("yellow" if sig_vulns else "green")
            schemes = sig_data.get("schemes", {})
            s_str = " ".join(f"{k}={'✓' if v else '✗'}" for k, v in schemes.items())
            console.print(f"  [{sig_color}]Firma:[/{sig_color}] {s_str} | {sig_vulns} vulnerabilidades")

        # Deep Resources
        dr_data = data.get("deep_resources", {})
        if dr_data.get("available") and (dr_data.get("suspicious_resources") or dr_data.get("embedded_databases")):
            dr_crit = len(dr_data.get("by_severity", {}).get("CRITICO", []))
            dr_color = "red" if dr_crit else ("yellow" if dr_data.get("suspicious_resources") else "green")
            console.print(f"  [{dr_color}]Recursos:[/{dr_color}] {len(dr_data.get('suspicious_resources',[]))} sospechosos, {len(dr_data.get('embedded_executables',[]))} ejecutables, {len(dr_data.get('embedded_databases',[]))} DBs")

        # Accessibility / Overlay
        ao_data = data.get("accessibility_overlay", {})
        if ao_data.get("available") and (ao_data.get("has_accessibility_service") or ao_data.get("has_overlay_permission")):
            ao_risk = ao_data.get("risk_level", "BAJO")
            ao_color = {"CRITICO": "red", "ALTO": "yellow", "MEDIO": "bright_yellow"}.get(ao_risk, "green")
            ao_text = (
                f"[bold {ao_color}]Accesibilidad: {'SÍ' if ao_data.get('has_accessibility_service') else 'NO'}[/bold {ao_color}] | "
                f"Overlay: {'SÍ' if ao_data.get('has_overlay_permission') else 'NO'} | "
                f"Riesgo: {ao_risk} | Hallazgos: {len(ao_data.get('code_findings', []))}"
            )
            console.print(Panel(ao_text, title="[bold]Accesibilidad / Overlay[/bold]", border_style=ao_color))

        # Intent/IPC
        ipc_data = data.get("intent_ipc", {})
        if ipc_data.get("available"):
            ipc_score = ipc_data.get("attack_surface_score", 0)
            ipc_color = "red" if ipc_score > 60 else ("yellow" if ipc_score > 30 else "green")
            console.print(f"  [{ipc_color}]IPC:[/{ipc_color}] {len(ipc_data.get('unprotected_components',[]))} sin proteger, {len(ipc_data.get('deep_links',[]))} deep links, score={ipc_score}/100")

        # OWASP Mobile Top 10 2024
        owasp_data = data.get("owasp_mobile", {})
        if owasp_data.get("available"):
            owasp_sev = owasp_data.get("overall_severity", "BAJO")
            owasp_color = {"CRITICO": "red", "ALTO": "yellow", "MEDIO": "bright_yellow", "BAJO": "green"}.get(owasp_sev, "white")
            console.print(f"\n  [bold {owasp_color}]OWASP Mobile Top 10 2024: {owasp_data.get('overall_score',0)}/100 - {owasp_sev}[/bold {owasp_color}]")
            ot = Table(title="OWASP Mobile Top 10 2024", box=box.ROUNDED, border_style="bright_blue")
            ot.add_column("ID", style="bold", width=4)
            ot.add_column("Categoría", width=38)
            ot.add_column("Sev.", width=10)
            ot.add_column("Score", width=8, justify="right")
            ot.add_column("Hallazgos", width=10, justify="right")
            for cat in owasp_data.get("categories", []):
                c_sev = cat.get("severity", "BAJO")
                c_color = {"CRITICO": "red", "ALTO": "yellow", "MEDIO": "bright_yellow", "BAJO": "green"}.get(c_sev, "white")
                ot.add_row(cat["id"], cat["name"], f"[{c_color}]{c_sev}[/{c_color}]", f"{cat.get('score',0)}/100", str(len(cat.get("findings", []))))
            console.print(ot)

        findings = risk.get("findings",[])[:12]
        if findings:
            ft = Table(title="Top Hallazgos", box=box.SIMPLE, border_style="bright_blue")
            ft.add_column("#", style="dim", width=3)
            ft.add_column("Sev.", width=10)
            ft.add_column("Detalle")
            for i, (sev, desc) in enumerate(findings, 1):
                c = {"CRITICO":"red","ALTO":"yellow","MEDIO":"bright_yellow","BAJO":"green","INFO":"dim"}.get(sev,"white")
                ft.add_row(str(i), f"[{c}]{sev}[/{c}]", desc)
            console.print(ft)

        # ── Tabla resumen total de hallazgos por severidad ──
        sev_counts = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0}
        for sev, _ in risk.get("findings", []):
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        total_findings = sum(sev_counts.values())
        sev_table = Table(title=f"📊 Resumen Total: {total_findings} hallazgos", box=box.ROUNDED, border_style="bright_blue")
        sev_table.add_column("Severidad", style="bold")
        sev_table.add_column("Cantidad", justify="right")
        sev_table.add_column("Barra", min_width=20)
        sev_colors = {"CRITICO": "red", "ALTO": "yellow", "MEDIO": "bright_yellow", "BAJO": "green", "INFO": "dim"}
        sev_icons = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🟢", "INFO": "⚪"}
        max_c = max(sev_counts.values()) if sev_counts.values() else 1
        for sev_name in ("CRITICO", "ALTO", "MEDIO", "BAJO", "INFO"):
            cnt = sev_counts.get(sev_name, 0)
            bar_len = int((cnt / max(max_c, 1)) * 20) if cnt else 0
            bar_str = "█" * bar_len
            sc = sev_colors.get(sev_name, "white")
            sev_table.add_row(
                f"[{sc}]{sev_icons.get(sev_name,'')} {sev_name}[/{sc}]",
                f"[{sc}]{cnt}[/{sc}]",
                f"[{sc}]{bar_str}[/{sc}]"
            )
        console.print(sev_table)

        console.print(Panel(
            f"Markdown: REPORTE_FORENSE.md\n"
            f"HTML: REPORTE_FORENSE.html\n"
            f"JSON: resultado.json\n"
            f"Directorio: {report_dir}",
            title="[bold green]Reportes Generados[/bold green]", border_style="green"))
    else:
        print(f"\n{'='*60}")
        print(f"  {risk.get('level_icon','')} RIESGO: {risk.get('score',0)}/100 - {risk.get('level','N/A')}")
        print(f"{'='*60}")
        print(f"  Paquete:    {manifest.get('package','N/A')}")
        print(f"  Permisos:   {len(manifest.get('permissions',[]))} ({len(manifest.get('dangerous_permission_details',[]))} peligrosos)")
        print(f"  Exportados: {len(manifest.get('exported_components',[]))}")
        print(f"  Trackers:   {trackers.get('total',0)}")
        print(f"  Secretos:   {total_secrets}")
        if ag.get("available"):
            print(f"  Androguard: {ag.get('class_count',0)} clases, {len(ag.get('dangerous_api_calls',[]))} APIs peligrosas")
        if quark.get("available"):
            print(f"  Quark:      {quark.get('threat_level','N/A')} ({len(quark.get('rules_matched',[]))} reglas)")
        if enjarify.get("available"):
            print(f"  Enjarify:   {enjarify.get('class_count',0)} clases convertidas")
        if yara_r.get("available"):
            print(f"  YARA:       {len(yara_r.get('matches',[]))} coincidencias ({yara_r.get('rules_loaded',0)} reglas)")
        if apkid.get("available"):
            print(f"  APKiD:      {len(apkid.get('packers',[]))} packers, {len(apkid.get('obfuscators',[]))} ofusc., {len(apkid.get('anti_analysis',[]))} anti-análisis")
        if lief_r.get("available"):
            print(f"  LIEF:       {lief_r.get('total_libs',0)} libs, {len(lief_r.get('dangerous_imports_found',[]))} imports peligrosos")
        ep_p = data.get("endpoints", {})
        if ep_p.get("available") and ep_p.get("total_endpoints", 0) > 0:
            print(f"  Endpoints:  {ep_p['total_endpoints']} hallazgos, {len(ep_p.get('unique_domains',[]))} dominios, {len(ep_p.get('endpoints_by_type',{}).get('internal_ips',[]))} IPs internas")
        inj_p = data.get("injection", {})
        if inj_p.get("available") and inj_p.get("total_vulnerabilities", 0) > 0:
            print(f"  Inyección:  {inj_p['total_vulnerabilities']} vulns ({len(inj_p.get('by_severity',{}).get('CRITICO',[]))} crit, {len(inj_p.get('by_severity',{}).get('ALTO',[]))} alto)")
        if crypto_cert.get("available"):
            print(f"  Cert X.509: {len(crypto_cert.get('cert_anomalies',[]))} anomalías")
        aw_p = data.get("androwarn", {})
        if aw_p.get("available"):
            print(f"  Androwarn:  {aw_p.get('severity','N/A')} ({aw_p.get('total_behaviors',0)} comportamientos)")
        fh_p = data.get("fuzzy_hashes", {})
        if fh_p.get("available"):
            print(f"  FuzzyHash:  ssdeep={'Sí' if fh_p.get('has_ssdeep') else 'No'}, tlsh={'Sí' if fh_p.get('has_tlsh') else 'No'}, DEX={len(fh_p.get('dex_hashes',[]))}")
        eo_p = data.get("entropy_obfuscation", {})
        if eo_p.get("available"):
            print(f"  Entropía:   media={eo_p.get('overall_entropy',0):.2f}, ofusc={eo_p.get('obfuscation_score',0)}/100, packed={len(eo_p.get('packed_files',[]))}")
        mi_p = data.get("mitre_attack", {})
        if mi_p.get("available"):
            print(f"  MITRE:      {mi_p.get('total_techniques',0)} técnicas en {len(mi_p.get('tactics',{}))} tácticas")
        tl_p = data.get("forensic_timeline", {})
        if tl_p.get("available"):
            print(f"  Timeline:   {tl_p.get('time_range',{}).get('total_events',0)} eventos, {len(tl_p.get('inconsistencies',[]))} inconsistencias")
        bc2_p = data.get("backdoor_c2", {})
        if bc2_p.get("available") and bc2_p.get("total_findings", 0) > 0:
            print(f"  Backdoor:   {bc2_p.get('total_findings',0)} indicadores (C2={'SÍ' if bc2_p.get('has_backdoor_indicators') else 'No'}, Spyware={'SÍ' if bc2_p.get('has_spyware_indicators') else 'No'})")
        epc_p = data.get("endpoint_classification", {})
        if epc_p.get("available"):
            rs_p = epc_p.get("risk_summary", {})
            print(f"  Endpoints:  C2={rs_p.get('c2_count',0)}, IL={rs_p.get('israeli_count',0)}, Vigil={rs_p.get('surveillance_count',0)}, TOR={rs_p.get('tor_count',0)}")
        exf_p = data.get("exfiltration", {})
        if exf_p.get("available"):
            exf_s = exf_p.get("summary", {})
            print(f"  Exfiltrac:  {exf_s.get('critical_chains',0)} cadenas críticas, {exf_s.get('high_risk_chains',0)} alto riesgo")
        sd_p = data.get("string_deobfuscation", {})
        if sd_p.get("available") and sd_p.get("total_decoded", 0) > 0:
            print(f"  Deobfusc:   {sd_p.get('total_decoded',0)} strings, {len(sd_p.get('interesting_strings',[]))} interesantes")
        sig_p = data.get("signature_scheme", {})
        if sig_p.get("available"):
            schemes = sig_p.get("schemes", {})
            s_str = " ".join(f"{k}={'✓' if v else '✗'}" for k, v in schemes.items())
            print(f"  Firma:      {s_str} | {len(sig_p.get('vulnerabilities',[]))} vulns")
        dr_p = data.get("deep_resources", {})
        if dr_p.get("available") and (dr_p.get("suspicious_resources") or dr_p.get("embedded_databases")):
            print(f"  Recursos:   {len(dr_p.get('suspicious_resources',[]))} sospechosos, {len(dr_p.get('embedded_executables',[]))} ejecutables, {len(dr_p.get('embedded_databases',[]))} DBs")
        ao_p = data.get("accessibility_overlay", {})
        if ao_p.get("available") and (ao_p.get("has_accessibility_service") or ao_p.get("has_overlay_permission")):
            print(f"  A11y/Ovrl:  Accesibilidad={'SÍ' if ao_p.get('has_accessibility_service') else 'NO'}, Overlay={'SÍ' if ao_p.get('has_overlay_permission') else 'NO'}, Riesgo={ao_p.get('risk_level','N/A')}")
        ipc_p = data.get("intent_ipc", {})
        if ipc_p.get("available"):
            print(f"  IPC:        {len(ipc_p.get('unprotected_components',[]))} sin proteger, {len(ipc_p.get('deep_links',[]))} deep links, score={ipc_p.get('attack_surface_score',0)}/100")
        owasp_p = data.get("owasp_mobile", {})
        if owasp_p.get("available"):
            obs = owasp_p.get("by_severity", {})
            print(f"  OWASP:      {owasp_p.get('overall_score',0)}/100 ({owasp_p.get('overall_severity','N/A')}) - {owasp_p.get('total_findings',0)} hallazgos [C:{obs.get('CRITICO',0)} A:{obs.get('ALTO',0)} M:{obs.get('MEDIO',0)} B:{obs.get('BAJO',0)}]")
        print(f"  Reportes:   {report_dir}")
        print(f"{'='*60}\n")


def analyze_single(target):
    target = target.strip().replace("'","").replace('"','')
    if not os.path.exists(target):
        rprint(f"[X] Archivo no encontrado: {target}", style="bold red")
        return
    ext = Path(target).suffix.lower().lstrip('.')
    if ext not in ('apk', 'apks', 'apkm', 'xapk'):
        rprint(f"[X] Extension no soportada: .{ext}", style="bold red")
        return

    if HAS_RICH:
        console.print(Panel(
            f"[cyan]Archivo:[/cyan] {os.path.basename(target)}\n"
            f"[cyan]Tipo:[/cyan] {ext.upper()}\n"
            f"[cyan]Tamano:[/cyan] {format_size(os.path.getsize(target))}",
            title="[bold blue]Iniciando Analisis Forense[/bold blue]", border_style="blue"))
    else:
        print(f"\n[*] Analizando: {os.path.basename(target)} ({ext.upper()})")

    engine = ApkilisEngine(target)
    data, report_dir = engine.run()
    display_results(data, report_dir)


def analyze_batch(directory):
    valid_exts = {'.apk', '.apks', '.apkm', '.xapk'}
    files = [os.path.join(directory, f) for f in os.listdir(directory)
             if Path(f).suffix.lower() in valid_exts]
    if not files:
        rprint("[X] No se encontraron archivos APK/APKM/XAPK.", style="bold red")
        return

    rprint(f"[+] {len(files)} archivos encontrados.\n", style="bold green")
    for i, f in enumerate(files, 1):
        if HAS_RICH:
            console.rule(f"[bold cyan]Archivo {i}/{len(files)}: {os.path.basename(f)}[/bold cyan]")
        else:
            print(f"\n{'='*60}\n  [{i}/{len(files)}] {os.path.basename(f)}\n{'='*60}")
        try:
            analyze_single(f)
        except Exception as e:
            rprint(f"[X] Error: {e}", style="bold red")
    rprint(f"\n[+] Lote completado: {len(files)} archivos.", style="bold green")


def main():
    while True:
        show_banner()
        if HAS_RICH:
            menu = Table(show_header=False, box=box.ROUNDED, border_style="bright_blue", padding=(0,2))
            menu.add_column("Opcion", style="bold yellow", width=6)
            menu.add_column("Descripcion", style="white")
            menu.add_row("1", "Analizar archivo individual (.apk, .apkm, .xapk, .apks)")
            menu.add_row("2", "Analisis por lotes (directorio completo)")
            menu.add_row("3", "Generar kit de analisis dinamico (Frida/ADB/Drozer/Objection)")
            menu.add_row("0", "Salir")
            console.print(menu)
            console.print()
            choice = console.input("[bold yellow]Apkilis > [/bold yellow]").strip()
        else:
            print("  1. Analizar archivo individual")
            print("  2. Analisis por lotes (directorio)")
            print("  3. Generar kit de analisis dinamico")
            print("  0. Salir\n")
            choice = input("Apkilis > ").strip()

        if choice == '0':
            rprint("\n[*] Sesion terminada.", style="bold red")
            break
        elif choice == '1':
            if HAS_RICH:
                target = console.input("[bold cyan]Ruta del archivo: [/bold cyan]").strip()
            else:
                target = input("Ruta del archivo: ").strip()
            analyze_single(target)
            input("\nPresione ENTER para continuar...")
        elif choice == '2':
            if HAS_RICH:
                directory = console.input("[bold cyan]Ruta del directorio: [/bold cyan]").strip()
            else:
                directory = input("Ruta del directorio: ").strip()
            directory = directory.strip().replace("'","").replace('"','')
            if os.path.isdir(directory):
                analyze_batch(directory)
            else:
                rprint("[X] Directorio no encontrado.", style="bold red")
            input("\nPresione ENTER para continuar...")
        elif choice == '3':
            if HAS_RICH:
                target = console.input("[bold cyan]Ruta del APK: [/bold cyan]").strip()
            else:
                target = input("Ruta del APK: ").strip()
            target = target.strip().replace("'","").replace('"','')
            if os.path.isfile(target):
                rprint("\n[*] Generando kit de analisis dinamico...", style="bold cyan")
                try:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    out_dir = os.path.join(os.path.dirname(target) or ".",
                                           f"dynamic_kit_{os.path.basename(target)}_{ts}")
                    os.makedirs(out_dir, exist_ok=True)
                    # Decompile APK first so ManifestAnalyzer gets a valid directory
                    tmp_decompiled = tempfile.mkdtemp(prefix="apkilis_dyn_")
                    decompiled_dir_tmp = os.path.join(tmp_decompiled, "decompiled")
                    try:
                        subprocess.run(
                            ['apktool', 'd', '-f', target, '-o', decompiled_dir_tmp],
                            check=True, capture_output=True, timeout=300)
                        manifest = ManifestAnalyzer.analyze(decompiled_dir_tmp)
                    except Exception as dec_err:
                        logger.warning(f"apktool fallo para kit dinamico: {dec_err}")
                        manifest = {"package": "", "activities": [], "services": [],
                                    "receivers": [], "providers": [], "permissions": [],
                                    "exported_components": [], "flags": {},
                                    "dangerous_permission_details": []}
                        decompiled_dir_tmp = None
                    structure = StructureAnalyzer.analyze(target, decompiled_dir_tmp)
                    result = DynamicAnalysisGenerator.generate(target, manifest, out_dir, structure)
                    # Cleanup temp decompiled dir
                    if tmp_decompiled and os.path.isdir(tmp_decompiled):
                        shutil.rmtree(tmp_decompiled, ignore_errors=True)
                    if result.get("available"):
                        n_frida = len(result.get("frida_scripts", {}))
                        n_adb = sum(len(c.get("commands",[])) for c in result.get("adb_commands",[]))
                        n_drozer = sum(len(c.get("commands",[])) for c in result.get("drozer_commands",[]))
                        rprint(f"\n[green]✅ Kit generado en: {out_dir}[/green]")
                        rprint(f"   Frida Scripts: {n_frida} | ADB: {n_adb} | Drozer: {n_drozer}", style="bold")
                    else:
                        rprint(f"[yellow]⚠ Kit parcial: {result.get('error','')}[/yellow]")
                except Exception as e:
                    logger.error(f"Error generando kit dinamico: {e}", exc_info=True)
                    rprint(f"[red][X] Error: {e}[/red]")
            else:
                rprint("[X] Archivo no encontrado.", style="bold red")
            input("\nPresione ENTER para continuar...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Sesion abortada.")
        sys.exit(0)
