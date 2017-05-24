# uso
## para cifrar
java -jar criptoanalisis.jar -c -e 17 -n 2231 -t "MENSAJE" -s 2

## para descrifrar
java -jar criptoanalisis.jar -d -e 17 -n 2231 -t "JV;CTU;RW;FF;"

## para cifrar con algoritmo alternativo
java -jar criptoanalisis.jar -c -e 17 -n 2231 -t "mensaje" -s 2 -a

## para descrifrar con algoritmo alternativo
java -jar criptoanalisis.jar -d -e 17 -n 2231 -t "jvcturwff" -s 2 -a
