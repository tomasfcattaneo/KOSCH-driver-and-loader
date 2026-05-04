# KOSCH: Driver y Loader para Interacción con el Kernel (PoC)

Este proyecto es una Prueba de Concepto (PoC) que demuestra la carga de un driver en el kernel de Windows, la comunicación segura entre el modo usuario y el modo kernel, y la implementación de primitivas de lectura/escritura de memoria y escaneo de patrones, con un enfoque en la interacción con procesos de juegos (ej. `hl.exe`).

## Propósito del Proyecto

El objetivo principal de KOSCH es proporcionar un framework básico y estable para la investigación de seguridad en el kernel de Windows y el desarrollo de herramientas de bajo nivel. Se enfoca en técnicas para:

- **Carga de Drivers Indetectable:** Utilizando un driver vulnerable conocido (`TBT.sys`) para cargar un driver personalizado en memoria, evitando la detección por parte de soluciones de seguridad tradicionales.
- **Comunicación Segura User-Kernel:** Implementando un mecanismo de comunicación robusto y aislado para intercambiar datos entre el loader (modo usuario) y el driver (modo kernel).
- **Primitivas de Memoria:** Desarrollando funciones esenciales para leer, escribir y escanear patrones en la memoria de procesos arbitrarios desde el kernel.
- **Evasión de Detección:** Incorporando técnicas para limpiar rastros forenses y evitar BSODs durante la operación.

## Componentes

El proyecto se divide en dos componentes principales:

1.  **Driver (`koshchei.sys`):**
    -   Se carga en el kernel de Windows.
    -   Implementa las primitivas de lectura/escritura de memoria (`Vx_Read`, `Vx_Write`).
    -   Permite el escaneo de patrones en la memoria de procesos remotos (`handle_pattern_scan`).
    -   Puede obtener la dirección base de módulos en procesos remotos, incluyendo procesos WOW64 (32-bit en sistemas de 64-bit) como `hl.exe`.
    -   Contiene funciones para ocultar/mostrar procesos (DKOM - Direct Kernel Object Manipulation).
    -   Se comunica con el loader a través de un buffer compartido en memoria.

2.  **Loader (`loader.exe`):**
    -   Aplicación en modo usuario que se encarga de la carga inicial del driver.
    -   Utiliza un driver vulnerable (`TBT.sys`) para obtener capacidades de lectura/escritura física en el kernel.
    -   Mapea el driver personalizado (`koshchei.sys`) en la memoria del kernel.
    -   Establece el canal de comunicación con el driver cargado.
    -   Envía comandos al driver para realizar operaciones como lectura de memoria, escaneo de patrones, etc.
    -   Realiza la limpieza de rastros forenses al finalizar.

## Método de Comunicación: El "NtClose Gate" y Buffer Compartido

La comunicación entre el `loader.exe` (modo usuario) y el `koshchei.sys` (modo kernel) es un aspecto crítico y se implementa de la siguiente manera:

1.  **Hook Temporal de `NtClose` (El "Gate"):**
    -   El loader identifica la dirección de la función `NtClose` en `ntoskrnl.exe` en el kernel.
    -   Instala un "hook" temporal sobre `NtClose`. Este hook no es persistente; se instala justo antes de cada llamada al driver y se elimina inmediatamente después.
    -   El hook redirige la ejecución a un pequeño shellcode (`NK_TEMPLATE`) que se encuentra en una región de memoria contigua asignada por el loader en el kernel.

2.  **Shellcode y Buffer Compartido:**
    -   El shellcode es el "gate" real. Su función principal es verificar si la llamada a `NtClose` proviene del loader (identificando el `KTHREAD` del loader).
    -   Si la llamada es del loader, el shellcode no ejecuta la `NtClose` original. En su lugar, salta a la función `Dx_Entry` de nuestro driver.
    -   El loader prepara un **buffer de comunicación** (`cmd_buf`) en su propio espacio de memoria de usuario. La dirección virtual de este buffer se pasa al driver a través de la estructura `NX_BRIDGE` (pre-rellenada en el driver mapeado).
    -   `Dx_Entry` en el driver recibe la dirección virtual del `cmd_buf` del loader.
    -   Para evitar violaciones de acceso a memoria (BSODs por SMAP/UMIP), el driver utiliza `MmCopyVirtualMemory` (obtenida dinámicamente) para copiar de forma segura los datos del `cmd_buf` del espacio de usuario al espacio de kernel, y viceversa para la respuesta.
    -   Este buffer compartido (`DX_BUF_SIZE`, actualmente 4KB) se utiliza para enviar comandos (`DX_HDR`, `DX_READ`, `DX_PATTERN_SCAN`, etc.) y recibir respuestas (`DX_RSP`).

3.  **Mecanismo Single-Thread:**
    -   Este diseño asume un modelo de comunicación "single-thread" o "request-response" simple. El loader envía un comando, espera la respuesta, y solo entonces puede enviar el siguiente.
    -   El hook temporal de `NtClose` garantiza que el sistema no se vea afectado por un hook persistente, reduciendo la superficie de ataque y la probabilidad de BSODs inesperados causados por otras partes del kernel que llamen a `NtClose` mientras el hook está activo.

## Logros Actuales

Hasta la fecha, el proyecto ha logrado con éxito:

-   **Carga Estable del Driver:** El driver se carga en el kernel sin causar BSODs y se comunica correctamente con el loader.
-   **Comunicación Robusta:** El mecanismo de "NtClose gate" y el buffer compartido con `MmCopyVirtualMemory` permiten un intercambio de datos seguro y fiable entre el modo usuario y el kernel.
-   **Lectura y Escritura de Memoria:** Las primitivas `Vx_Read` y `Vx_Write` funcionan correctamente para acceder a la memoria de procesos remotos.
-   **Escaneo de Patrones:** La función `handle_pattern_scan` es capaz de buscar patrones de bytes específicos en la memoria de procesos remotos, incluso en procesos WOW64 (32-bit) como `hl.exe`.
-   **Detección de Módulos (HL.EXE):** El driver puede identificar la dirección base de `hl.exe` (y otros módulos principales) en procesos de 32 bits, lo cual es fundamental para el desarrollo de cheats.
-   **Limpieza de Rastros:** El loader realiza una limpieza de rastros forenses (`MmUnloadedDrivers`, `PiDDBCacheTable`) para dificultar la detección del driver cargado.
-   **Estabilidad General:** El sistema ha demostrado ser estable, sin BSODs durante las pruebas de las funcionalidades implementadas.

## Output de Ejemplo (Interacción con HL.EXE)

```
C:\Users\y1nt0\Desktop\KOSCHH\loader\build\bin\Release>loader.exe
[INF] === init ===
[INF] [Step 0] privilege + environment checks
[INF] [Step 1] enumerating kernel modules
[INF] ntoskrnl: ntoskrnl.exe @ 0xFFFFF8003FE00000 (0x1046000)
[INF] [Step 2] loading driver
[INF] [Step 3] discovering ntoskrnl physical base
[INF] ntoskrnl phys: 0x2400000
[INF] [Step 4] verifying kernel R/W
[INF]   ntoskrnl MZ verified via VA read
[INF] [Step 5] installing NtClose gate
[INF] NtClose: VA=0xFFFFF8004043E0A0 PA=0x2A3E0A0
[INF] gate pool: VA=0xFFFFD20020967000 PA=0x4227FA000
[INF] KTHREAD: 0xFFFF8D011EB84080
[INF] NtClose gate ready (no persistent hook)
[INF] [Step 6] parsing driver PE
[INF] PE: base=0x140000000 size=0x7000 entry=0x1CC0 sects=5 relocs=0 imports=1
[INF] [Step 7] mapping driver into kernel
[INF]   image pool: VA=0xFFFFD20020BF8000 PA=0x42268D000 size=0x7000
[INF]   sections copied
[INF]   applied 0 relocations (delta=0xFFFFD1FEE0BF8000)
[INF]   IAT patched (1 import descriptors)
[INF]   mapped: base=0xFFFFD20020BF8000 entry=0xFFFFD20020BF9CC0
[INF] [Step 8] pre-filling NX_BRIDGE
[INF]   bootstrap written at 0xFFFFD20020BFC000 (pid=10316)
[INF] [Step 9] calling DriverEntry
[INF]   DriverEntry returned 0x0
[INF] [Step 10] dispatch_va=0xFFFFD20020BF9D90
[INF]   ping OK
[INF] [Step 10.1] Testing memory read via shared memory...
[INF]   Read via Shared Memory: OK (found MZ at ntoskrnl)
[INF] [Step 10.3] Testing pattern scan for ntoskrnl MZ header...
[INF]   Pattern Scan: OK (found MZ at 0xFFFFF8003FE00000)
[INF] [Step 10.4] Interacting with HL.EXE...
[INF]   Found HL.EXE with PID: 5108
[INF]   HL.EXE Base Address: 0x1400000
[INF]   Successfully read Game MZ Header!
[INF]   Scanning for HL function pattern...
[INF]   Pattern found in game at: 0x1401344
[INF] [Step 11] cleaning traces
[INF] cleaning forensic traces
[INF] [Step 12] cleanup, hold
[INF] NtClose gate freed
[INF] Zv: 3798 IOCTLs issued
^C
```

## Próximos Pasos

Con estas primitivas establecidas, el proyecto puede expandirse para incluir funcionalidades más avanzadas como:

-   Implementación de `driver_write_memory` en el loader para modificar valores en el juego.
-   Desarrollo de un sistema de "Pattern Write" para parchear funciones o datos en tiempo real.
-   Extensión de `handle_get_module_base` para enumerar todos los módulos (DLLs) de un proceso remoto, incluyendo los módulos de 32 bits en procesos WOW64.
-   Creación de una interfaz de usuario para controlar las funcionalidades del cheat/cliente.
-   Integración de lógicas de botting o automatización de acciones en el juego.

---

**Nota:** Este proyecto es solo para fines educativos y de investigación. El uso de estas técnicas para hacer trampas en juegos online puede resultar en la prohibición de la cuenta y es generalmente desaconsejado.
