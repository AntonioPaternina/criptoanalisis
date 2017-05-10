# uso
## para cifrar
java -jar criptoanalisis.jar -c -e 17 -n 2231 -t "mensaje" -s 2

## para descrifrar
java -jar criptoanalisis.jar -d -e 17 -n 2231 -t "jvcturwff" -s 2

## para cifrar con algoritmo alternativo
java -jar criptoanalisis.jar -c -e 17 -n 2231 -t "mensaje" -s 2 -a

## para descrifrar con algoritmo alternativo
java -jar criptoanalisis.jar -d -e 17 -n 2231 -t "jvcturwff" -s 2 -a

# ayuda
usage: java -jar criptoanalisis.jar [-a] [-c] [-d] [-e <arg>] [-n <arg>] [-s
       <arg>] [-t <arg>]
Ayuda Utilidad Criptoanálisis
     -a,--algoritmo-alternativo   algoritmo alternativo
     -c,--cifrar                  cifrar mensaje
     -d,--descifrar               descifrar mensaje
     -e,--encryption <arg>        valor e de la llave pública
     -n,--modulo <arg>            el valor de n de la llave pública
     -s,--segmentos <arg>         número de segmentos
     -t,--texto <arg>             texto a procesar
Fin de la ayuda
