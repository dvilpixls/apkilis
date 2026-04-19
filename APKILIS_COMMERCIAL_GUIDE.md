# APKILIS — Guía de Integración, Licencia y Comercialización

**Para:** DevlsPixls / Pixls
**Versión:** 1.0 (2026-04)
**Alcance:** Integración del módulo Jadx, licencia para venta perpetua pago único, publicación en GitHub y configuración de venta internacional.

---

## Parte 1 — Integración del módulo Jadx en `apkilis.py`

### 1.1 Copiar la clase `JadxDecompiler`

Abre `apkilis.py` y busca la línea:

```python
class ApkilisEngine:
```

Está alrededor de la **línea 11060**. Justo **antes** de esa línea, pega la clase completa `JadxDecompiler` que está en el archivo `apkilis_jadx_module.py` (desde `class JadxDecompiler:` hasta el cierre de `_score_risk`).

No copies los comentarios del encabezado del archivo ni el bloque de imports inicial — esos imports (`os`, `re`, `shutil`, `subprocess`, `tempfile`, `logging`, `Path`) ya los tienes en tu archivo principal.

### 1.2 Agregar jadx al pre-flight check

Busca en `ApkilisEngine._preflight_check()` la lista `checks`. Está alrededor de la **línea 11072**. Agrega una entrada:

```python
checks = {
    "apktool": {"required": True, "cmd": ["apktool", "--version"]},
    "jarsigner": {"required": False, "cmd": ["jarsigner", "-help"]},
    "keytool": {"required": False, "cmd": ["keytool", "-help"]},
    "apkid": {"required": False, "cmd": ["apkid", "--version"]},
    "jadx": {"required": False, "cmd": ["jadx", "--version"]},   # ← NUEVA LÍNEA
}
```

### 1.3 Agregar el step al pipeline

Busca en `ApkilisEngine.run()` la lista `steps`. Está alrededor de la **línea 11151**. Después de la línea de Enjarify, agrega:

```python
("Enjarify: conversion DEX a JAR", self._step_enjarify),
("Jadx: decompilacion Java y analisis profundo", self._step_jadx),   # ← NUEVA LÍNEA
("YARA: escaneo de reglas y firmas", self._step_yara),
```

### 1.4 Agregar el método `_step_jadx`

Busca el método `_step_enjarify` en `ApkilisEngine`. Está alrededor de la **línea 11352**. Justo después de ese método, pega:

```python
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
```

### 1.5 (Opcional) Integrar con el RiskScorer

Si quieres que los hallazgos de jadx pesen en el score final, busca `self._step_risk` en `ApkilisEngine.run()` y agrega `jadx=self.data.get("jadx")` a los kwargs de `RiskScorer.calculate()`. Luego en `RiskScorer.calculate()` agrega manejo del parámetro. Esto es opcional pero recomendable — los `high_risk_indicators` de jadx son señales muy fuertes.

### 1.6 (Opcional) Mostrar resumen en el dashboard

En `display_results()` o `display_cyberpunk_dashboard()`, agrega un bloque de resumen:

```python
jx_p = data.get("jadx", {})
if jx_p.get("available"):
    n_risks = len(jx_p.get("high_risk_indicators", []))
    print(f"  Jadx:       {jx_p.get('java_files_count',0)} archivos Java, "
          f"{jx_p.get('findings_count',0)} hallazgos, "
          f"{n_risks} indicadores riesgo")
```

### 1.7 Instalación de jadx en el sistema

Para que jadx esté disponible, el usuario final debe instalarlo. Instrucciones para Parrot OS / Debian / Ubuntu:

```bash
# Opción 1: descargar release oficial (recomendado — más actualizado)
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
sudo mkdir -p /opt/jadx
sudo unzip jadx-1.5.0.zip -d /opt/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
sudo ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui

# Opción 2: desde apt (puede estar desactualizado)
sudo apt install jadx

# Verificar
jadx --version
```

Documenta esto en el README del repo para que tus compradores lo hagan.

### 1.8 Prueba de la integración

```bash
# Prueba con un APK pequeño primero (<20 MB) para validar que todo corre
python3 apkilis.py

# Verifica en el pre-flight que aparezca "jadx: ✓"
# Al terminar, en el directorio de reporte debe existir jadx_output/
# y data["jadx"]["available"] debe ser True
```

Si el step tarda más de 7 minutos (420s) en APKs grandes, incrementa `timeout_sec`. Para apps bancarias o Facebook-tier puedes necesitar 900s.

---

## Parte 2 — Licencia EULA para pago único perpetuo

Copia el siguiente bloque a un archivo **`LICENSE.txt`** (o `EULA.txt`) que incluirás en el ZIP de venta. Esta es una EULA comercial estándar adaptada para software "un pago, es tuyo, para siempre".

**IMPORTANTE: esto es una plantilla basada en prácticas comunes. No soy abogado y esto no es asesoría legal. Para casos importantes, considera hacer que un abogado en México lo revise — especialmente si llegas a vender volumen alto.**

### Plantilla EULA (pegar en `LICENSE.txt`)

```
═══════════════════════════════════════════════════════════════════════════════
APKILIS - CONTRATO DE LICENCIA DE USUARIO FINAL (EULA)
Version 1.0 - Vigente desde: [FECHA]
Licenciante: [Tu nombre legal], operando bajo la marca "DevlsPixls"
Ubicacion: Xalapa, Veracruz, Mexico
Contacto: [tu-correo@dominio.com]
═══════════════════════════════════════════════════════════════════════════════

LEA CUIDADOSAMENTE ESTE CONTRATO ANTES DE UTILIZAR EL SOFTWARE. AL INSTALAR,
COPIAR O UTILIZAR APKILIS ("el Software"), USTED ACEPTA QUEDAR VINCULADO POR
LOS TERMINOS DE ESTE CONTRATO. SI NO ESTA DE ACUERDO, NO UTILICE EL SOFTWARE
Y SOLICITE REEMBOLSO DENTRO DE LOS 14 DIAS POSTERIORES A LA COMPRA.

1. DEFINICIONES

   1.1 "Software" se refiere a APKILIS, incluyendo su codigo fuente, binarios,
       documentacion, scripts, reglas YARA, y cualquier material asociado
       entregado al Licenciatario.

   1.2 "Licenciatario" se refiere a la persona fisica o juridica que adquiere
       la licencia mediante pago unico.

   1.3 "Licenciante" se refiere al titular de los derechos patrimoniales del
       Software, identificado al inicio de este documento.

2. OTORGAMIENTO DE LICENCIA

   2.1 Mediante el pago unico de la contraprestacion acordada, el Licenciante
       otorga al Licenciatario una licencia NO EXCLUSIVA, PERPETUA,
       INTRANSFERIBLE, MUNDIAL y LIMITADA para:

       a) Instalar y utilizar el Software en un numero ilimitado de maquinas
          de uso personal o profesional del Licenciatario.
       b) Utilizar el Software para realizar analisis de seguridad sobre
          aplicaciones Android cuya evaluacion este autorizada legalmente
          (propias, de clientes con consentimiento escrito, o en programas
          de bug bounty autorizados).
       c) Modificar el codigo fuente para uso interno del Licenciatario.
       d) Generar reportes comerciales (peritajes, auditorias, bug bounty)
          usando el Software como herramienta de trabajo.

   2.2 La licencia es PERPETUA: una vez adquirida, el Licenciatario conserva
       el derecho de uso de la version adquirida indefinidamente, sin
       necesidad de renovacion ni pagos adicionales.

3. RESTRICCIONES

   El Licenciatario NO podra:

   3.1 Revender, redistribuir, sublicenciar, alquilar, arrendar, prestar ni
       transferir el Software ni su codigo fuente a terceros.

   3.2 Publicar el codigo fuente total o sustancialmente parcial en
       repositorios publicos, foros, torrents o cualquier medio que lo haga
       accesible a personas que no hayan adquirido su propia licencia.

   3.3 Remover, alterar u ocultar avisos de copyright, marcas comerciales o
       atribuciones de autoria presentes en el Software.

   3.4 Utilizar el Software para analizar aplicaciones sin autorizacion legal
       del propietario o del programa de bug bounty correspondiente. El
       Licenciatario asume responsabilidad exclusiva por el uso que de a la
       herramienta.

   3.5 Incorporar el Software dentro de otro producto comercial para
       reventa, sin autorizacion escrita previa del Licenciante.

4. ACTUALIZACIONES

   4.1 El Licenciante PUEDE, a su sola discrecion, ofrecer actualizaciones
       al Licenciatario.

   4.2 Actualizaciones menores (patches y correcciones de la version
       adquirida) seran provistas sin costo adicional al correo registrado
       durante los primeros 12 meses posteriores a la compra.

   4.3 Las versiones MAYORES (v2.0 → v3.0) pueden requerir una nueva
       licencia. Esto no afecta el derecho perpetuo del Licenciatario sobre
       la version originalmente adquirida.

5. PROPIEDAD INTELECTUAL

   5.1 El Software es propiedad exclusiva del Licenciante. Esta licencia NO
       transfiere derechos de propiedad; unicamente concede los derechos de
       uso descritos en la Seccion 2.

   5.2 El Licenciante conserva todos los derechos, titulos e intereses sobre
       el Software, incluyendo todos los derechos de autor y otros derechos
       de propiedad intelectual asociados.

6. GARANTIA LIMITADA Y LIMITACION DE RESPONSABILIDAD

   6.1 EL SOFTWARE SE PROVEE "TAL COMO ESTA" ("AS IS"), SIN GARANTIAS
       EXPRESAS O IMPLICITAS, INCLUYENDO PERO NO LIMITADO A GARANTIAS DE
       COMERCIALIZACION, IDONEIDAD PARA UN PROPOSITO PARTICULAR, O NO
       INFRACCION.

   6.2 EN NINGUN CASO EL LICENCIANTE SERA RESPONSABLE POR DANOS INDIRECTOS,
       INCIDENTALES, ESPECIALES, CONSECUENTES O PUNITIVOS, INCLUYENDO
       PERDIDA DE BENEFICIOS, INTERRUPCION DE NEGOCIO, PERDIDA DE DATOS O
       CUALQUIER OTRO PERJUICIO DERIVADO DEL USO O IMPOSIBILIDAD DE USO DEL
       SOFTWARE, AUN SI HUBIERA SIDO ADVERTIDO DE LA POSIBILIDAD DE TALES
       DANOS.

   6.3 LA RESPONSABILIDAD TOTAL DEL LICENCIANTE BAJO ESTE CONTRATO NO
       EXCEDERA EL MONTO EFECTIVAMENTE PAGADO POR EL LICENCIATARIO POR LA
       LICENCIA.

7. USO ETICO Y LEGAL

   7.1 El Licenciatario se compromete a utilizar el Software unicamente con
       fines legales y eticos, incluyendo investigacion de seguridad
       autorizada, analisis forense legitimo, bug bounty en programas
       autorizados, y evaluacion de aplicaciones de su propiedad.

   7.2 El uso del Software para actividades ilicitas, violacion de privacidad
       de terceros, o analisis no autorizado de aplicaciones de propiedad
       ajena es contrario a este contrato y queda prohibido.

8. TERMINACION

   8.1 Esta licencia se termina automaticamente si el Licenciatario incumple
       materialmente cualquier termino. Al terminar, el Licenciatario debera
       destruir todas las copias del Software.

   8.2 Las clausulas de Propiedad Intelectual, Limitacion de Responsabilidad
       y Ley Aplicable sobreviven a la terminacion.

9. POLITICA DE REEMBOLSO

   9.1 El Licenciatario puede solicitar reembolso total dentro de los 14
       dias calendario posteriores a la compra, siempre que certifique la
       destruccion de todas las copias del Software en su poder.

   9.2 Los reembolsos solicitados despues de 14 dias quedan a discrecion del
       Licenciante.

10. LEY APLICABLE

    10.1 Este contrato se rige por las leyes de los Estados Unidos Mexicanos.
    10.2 Cualquier disputa sera sometida a los tribunales competentes de
         Xalapa, Veracruz, Mexico.

11. ACEPTACION

    Al instalar, copiar o utilizar el Software, el Licenciatario confirma que
    ha leido, entendido y aceptado los terminos de este contrato.

═══════════════════════════════════════════════════════════════════════════════
```

**Notas importantes sobre esta EULA:**

- Reemplaza `[Tu nombre legal]`, `[FECHA]` y `[tu-correo@dominio.com]` antes de publicarla.
- La cláusula 3.2 (no redistribuir código) es la que protege tu modelo de negocio. Es similar a cómo Sublime Text, Beyond Compare y otros venden.
- La cláusula 9 (reembolso 14 días) la exigen Lemon Squeezy, Paddle y la UE (derecho de desistimiento). Es estándar y aumenta conversión.
- No estás bloqueando uso en bug bounty ni uso profesional — eso vende más. Solo bloqueas reventa y redistribución.

---

## Parte 3 — Estructura de GitHub

Tu setup ideal tiene **dos repositorios** y **una landing page**:

### 3.1 Repo privado: `APKILIS` (código fuente completo)

- **Visibilidad:** privado.
- **Licencia:** la EULA de arriba en `LICENSE.txt`.
- **Uso:** versionado interno, donde desarrollas. Nunca se hace público.
- **Quién accede:** solo tú. Opcionalmente, compradores VIP que paguen el tier con acceso continuo al repo (más abajo explico este modelo).

### 3.2 Repo público: `apkilis-landing` (marketing + documentación)

- **Visibilidad:** público.
- **Contenido:**
  - README.md con:
    - Descripción, features, screenshots (¡importantísimo!)
    - Comparativa honesta vs MobSF
    - Lista de módulos
    - Requisitos del sistema
    - Link a la página de compra
    - Capturas del dashboard cyberpunk (tu vibe es un diferenciador real)
  - Carpeta `docs/` con documentación técnica, ejemplos de reportes generados (sin el APK analizado, solo reportes de APKs de prueba que sean legales como F-Droid apps).
  - `CHANGELOG.md`: historial de versiones.
  - `examples/`: reportes de ejemplo generados por APKILIS (HTML/JSON/MD) para que se vea la calidad del output.
  - **NO SUBAS** el código fuente aquí.
- **Licencia del repo:** CC-BY-4.0 (solo aplica a la documentación, no al software).

Este repo es tu **vitrina pública**. Los "stars" en GitHub son credibilidad gratuita que genera confianza para comprar.

### 3.3 Landing page

Dos opciones según tu tiempo:

**Opción A — GitHub Pages (gratis, rápido):**
Habilitado desde `apkilis-landing`. Un README bonito con imágenes es suficiente para empezar.

**Opción B — Dominio propio (recomendado a medio plazo):**
Registra `apkilis.com` o `apkilis.dev` (~$10-15/año en Namecheap o Porkbun). Hospeda en Cloudflare Pages o Netlify (gratis). Un one-pager con:
- Hero con screenshot del dashboard
- Lista de features
- Comparativa vs MobSF
- Testimonials (cuando tengas)
- Botón "Comprar — $29 USD pago único"
- FAQ

Para diseño, usa plantillas gratis como [Astro](https://astro.build) con [Astro Paper](https://github.com/satnaing/astro-paper) o [Tailwind UI landing templates](https://tailwindui.com).

### 3.4 Subir el código al repo privado

```bash
cd ~/path/to/apkilis
git init
git add apkilis.py LICENSE.txt README.md requirements.txt
git commit -m "v2.0: release inicial comercial"

# Crear repo privado en GitHub (via web o gh CLI)
gh repo create APKILIS --private --source=. --remote=origin

git push -u origin main
```

Usa tags para marcar versiones:
```bash
git tag -a v2.0 -m "Release v2.0 — Primer release comercial"
git push origin v2.0
```

Cuando vendes, **no** das acceso al repo directamente. Exportas un ZIP del tag correspondiente:

```bash
git archive --format=zip --prefix=apkilis-v2.0/ v2.0 -o apkilis-v2.0.zip
```

Ese ZIP es lo que subes como "digital product" a la plataforma de venta.

---

## Parte 4 — Plataforma de venta

Para pago único internacional desde México, las mejores opciones en 2026 son:

### 4.1 Lemon Squeezy (RECOMENDADA)

**Pros:**
- Merchant of Record (MoR): ellos manejan IVA, VAT europeo, sales tax, facturación. Tú recibes neto y no te preocupas de impuestos internacionales.
- Integración de license keys automática (útil para activación futura).
- Soporta USD, EUR, y otros.
- Fee: 5% + $0.50 USD por transacción.
- Rápido de configurar (1 tarde).
- Paga a cuenta bancaria mexicana vía Wise o directamente.

**Contras:**
- Necesitas cuenta bancaria a nombre tuyo o RFC si facturas local.

**Setup:**
1. Regístrate en [lemonsqueezy.com](https://lemonsqueezy.com).
2. Crea un "Store" llamado "DevlsPixls" o "APKILIS".
3. Crea un producto "digital product":
   - Nombre: APKILIS v2.0 — Forensic Android Analyzer
   - Precio: $29 USD (o $19 early bird)
   - Tipo: single payment
   - Archivo: sube el ZIP
   - Licencia: activa "generate license keys" (te da un key único por compra, útil para control)
4. Conecta tu cuenta bancaria o Wise.
5. El checkout URL que te genera va en el botón "Comprar" de tu landing.

### 4.2 Polar.sh

Muy similar a Lemon Squeezy, más orientado a devs y open source. También MoR. Fees ligeramente menores (4%). Buena alternativa si Lemon Squeezy te da problemas.

### 4.3 Gumroad

Más simple pero:
- Fees más altos (10% efectivo en 2026).
- No es MoR: tú eres responsable de impuestos internacionales.
- Menos profesional en percepción.

Úsalo solo si quieres algo en 15 minutos sin pensar.

### 4.4 NO recomendado para este caso

- **Stripe directo:** requiere mucho setup legal (facturación, impuestos por país).
- **PayPal solo:** mucha fricción, disputas frecuentes.
- **Mercado Pago / OpenPay:** solo si vendes principalmente a México. Para internacional queda corto.

### 4.5 Flujo de entrega al comprador

El comprador:
1. Paga en Lemon Squeezy.
2. Recibe email con link de descarga del ZIP + license key.
3. Descarga, lee el README, instala dependencias.
4. Ejecuta `python3 apkilis.py`.

Tú:
1. Recibes notificación de venta.
2. Los fondos se acumulan en Lemon Squeezy y se liquidan a tu cuenta cada semana/mes.

---

## Parte 5 — Estructura del ZIP que entregas

```
apkilis-v2.0.zip
└── apkilis-v2.0/
    ├── apkilis.py                    # El script principal
    ├── LICENSE.txt                   # Tu EULA
    ├── README.md                     # Instrucciones de uso
    ├── INSTALL.md                    # Guía de instalación paso a paso
    ├── CHANGELOG.md                  # Historial de versiones
    ├── requirements.txt              # Deps Python (pip install -r)
    ├── requirements-optional.txt     # Deps avanzadas (androguard, etc.)
    ├── rules/                        # (Si tienes) reglas YARA propias
    ├── docs/
    │   ├── modules.md                # Descripción de cada módulo
    │   ├── external-tools.md         # Guía apktool/jadx/etc.
    │   └── troubleshooting.md
    └── examples/
        └── sample_report/            # Reporte de ejemplo generado
            ├── report.html
            └── report.json
```

El archivo `INSTALL.md` es crítico — muchos compradores no son expertos en Python. Incluye comandos copy-paste para Ubuntu, Debian, Parrot OS, y opcionalmente WSL2 en Windows.

---

## Parte 6 — Checklist antes del primer release comercial

- [ ] Integrar módulo Jadx y probar con 3 APKs distintos (pequeño, mediano, grande).
- [ ] Escribir README.md profesional con screenshots.
- [ ] Escribir INSTALL.md con comandos exactos.
- [ ] Personalizar EULA (nombre, fecha, correo).
- [ ] Crear repo privado `APKILIS` y push del código.
- [ ] Crear repo público `apkilis-landing` con marketing.
- [ ] Generar ZIP de distribución con `git archive`.
- [ ] Registrar cuenta en Lemon Squeezy.
- [ ] Subir ZIP y configurar producto.
- [ ] Probar checkout con tarjeta propia (Lemon Squeezy permite modo sandbox).
- [ ] Publicar landing page.
- [ ] Anuncio inicial: tu bio en HackerOne, X/Twitter, /r/netsec, Reddit, discord de bug bounty, Slack de DragonJAR, comunidades hispanas de infosec.

---

## Parte 7 — Estrategia de precio y lanzamiento (recomendación)

**Fase 1 — Early bird (primer mes):**
- Precio: **$19 USD**
- Mensaje: "Lanzamiento. 100 primeras licencias a precio early bird."
- Objetivo: 20-50 ventas. Reviews. Testimonials. Detectar bugs en usuarios reales.

**Fase 2 — Precio establecido:**
- Precio: **$39 USD**
- Incluye updates de la v2.x por 12 meses.
- Licencia perpetua para la versión adquirida.

**Fase 3 — Versión mayor (cuando saques v3.0):**
- Los usuarios de v2.x pueden upgrade con descuento (~$20).
- Nuevos clientes pagan $49-59.

Nunca bajes el precio base. Ofertas por tiempo limitado sí (Black Friday, aniversario), pero el precio "de lista" debe subir con el tiempo, no bajar. Es señal de madurez del producto.

---

## Parte 8 — Qué hacer después de las primeras ventas

1. **Pide testimonials** a los que te compren. Un tweet o párrafo que puedas citar en la landing vale oro.
2. **Escribe writeups técnicos** usando APKILIS en bug bounties reales (con disclosure). Cada writeup es un anuncio permanente.
3. **Publica una versión community limitada** en GitHub bajo PolyForm Noncommercial 1.0.0 si quieres un funnel de marketing (opcional, pero funciona: la gente prueba la community y convierte a Pro).
4. **Ofrece servicios de consultoría** basados en APKILIS. "Análisis forense de APK con reporte pericial: $500 USD." Esto es más rentable por hora que vender el software solo.

---

**Cualquier duda sobre alguno de estos pasos me preguntas.** No tengas prisa — mejor salir con un producto pulido en un mes que con algo a medias en una semana. Pero tampoco persigas la perfección: el primer release siempre tiene bugs, y eso está bien.
