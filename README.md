# scapyLeds
Network Noise Visual Indicator

## Descripción
El propósito de este pequeño proyecto es concientizar de una forma visual y divertida sobre distintos niveles de 'ruido' que pueden generar algunas herramientas populares utilizadas en la etapa de preparación de un Pen Test, como NMAP y WPScan (entre los mas populares). El proyecto consta de utilizar una raspberry pi y su header de GPIO para controlar una matriz de 20 LEDs que actuarán como vúmetros de red para reflejar con una latencia relativamente baja lo que está transitando por la red.

El escenario de laboratorio ideal contempla una máquina atacante, otra objetivo, un switch administrable con capacidad de hacer Port Mirroring, y la raspberry pi con la matriz de LEDs. Con el switch administrable podremos copiar el trafico que asociado al equipo objetivo hacia la raspberry pi, pudiendo observar visualmente el efecto que tienen los distintos parámetros de las herramientas populares, concientizando que algunos métodos son mas rápidos pero mucho mas agresivos.

## Requierimientos
- Una raspberry pi: Para este proyecto se utilizó una raspberry pi 3B+
- Una plaqueta con 20 LEDs: Para este proyecto se utilizaron 4 GPIOs para las filas y 5 GPIOs para las columnas.

### Plaqueta LED
WORK IN PROGRESS.


