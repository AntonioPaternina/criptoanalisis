
package co.edu.poli.seguridad.informacion.criptoanalisis;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

import static sun.security.krb5.Confounder.intValue;

public class Criptografia {

    // private Logger logger =
    // LoggerFactory.getLogger(this.getClass().getName());

    private int e;
    private int n;
    private String line;
    private int seg;
    private char cifrando;
    public static final int ALFABETO = 27;

    public Criptografia(int e, int n, String texto, int segmentos, char cifrando) {
        this.e = e;
        this.n = n;
        this.line = texto;
        this.seg = segmentos;
        this.cifrando = cifrando;
    }

    public void ejecutar() throws IOException {

        int[] arr = factorizaciones(n);
        int p = arr[0];
        int q = arr[1];

        int phi = (p - 1) * (q - 1);

        BigInteger biE = new BigInteger(String.valueOf(e));
        BigInteger biD = biE.modInverse(new BigInteger(String.valueOf(phi)));
        BigInteger biN = new BigInteger(String.valueOf(n));

        PrintWriter out = new PrintWriter(System.out);
        out.println("la llave privada es " + biD + " " + n);
        out.print("el resultado es: ");

        boolean esCifrar = (cifrando == 'c' ? true : false);
        List<String> segmentos = obtenerSegmentos(esCifrar);
        for (String segmento : segmentos) {
            long segmentoOriginalEnDecimal = 0;
            for (int i = 0; i < segmento.length(); i++) {
                char caracter = segmento.charAt(segmento.length() - 1 - i);
                int valor = valorDeCaracter(caracter);
                segmentoOriginalEnDecimal += valor * Math.pow(ALFABETO, i);
            }

            BigInteger segmentoProcesadoEnDecimal;
            if (esCifrar) {
                BigInteger biSuma = new BigInteger(String.valueOf(segmentoOriginalEnDecimal));
                segmentoProcesadoEnDecimal = biSuma.modPow(biE, biN);
            } else {
                BigInteger biSuma = new BigInteger(String.valueOf(segmentoOriginalEnDecimal));
                segmentoProcesadoEnDecimal = biSuma.modPow(biD, biN);
            }

            String segmentoEnBaseDelAlfabeto = Integer.toString(segmentoProcesadoEnDecimal.intValue(), ALFABETO);

            for (char caracter : segmentoEnBaseDelAlfabeto.toCharArray()) {
                int caracterEnDecimal = Integer.parseInt(String.valueOf(caracter), ALFABETO);
                char caracterDecodificado = valorDeCaracter(caracterEnDecimal);
                out.print(caracterDecodificado);
            }
            out.print(";");
        }
        out.println();
        out.close();
    }

    private List<String> obtenerSegmentos(boolean cifrar) {
        List<String> cadenas;
        if (cifrar) {
            cadenas = segmentarCadena(line, seg);
        } else {
            cadenas = Arrays.asList(StringUtils.split(line, ";"));
        }
        return cadenas;
    }

    public void ejecutar2() throws IOException {
        PrintWriter out = new PrintWriter(System.out);
        int[] arr = factorizaciones(n);
        int p = arr[0];
        int q = arr[1];
        int fi = (p - 1) * (q - 1);
        int d = BigInteger.valueOf(e).modInverse(BigInteger.valueOf(fi)).intValue();
        out.println("la llave privada es " + d + " " + n);
        out.print("el resultado es: ");
        int pots = 27;
        // for (seg = 0; pots < n; seg++)
        // pots*=27;
        if (cifrando == 'd') {
            StringTokenizer st = new StringTokenizer(line);
            seg = line.indexOf(';');
            if (seg == -1)
                seg = 1;
            line = line.replaceAll(";", "");
        }
        long suma = 0;
        for (int i = 0; i < line.length(); i++) {
            int pot = seg - 1 - (i % seg);
            suma += valorDeCaracter(line.charAt(i)) * Math.pow(27, pot);
            if ((i + 1) % seg == 0) {
                // para cifrar con e, para decifrar con d
                String bin = "";
                if (cifrando == 'c')
                    bin = Long.toBinaryString(e);
                else if (cifrando == 'd')
                    bin = Long.toBinaryString(d);
                long res = 1;
                long m = suma;
                for (int j = bin.length() - 1; j >= 0; j--) {
                    if (bin.charAt(j) == '1')
                        res = (res * m) % n;
                    m = (m * m) % n;
                }
                m = res;
                StringBuffer sb = new StringBuffer();
                pots = 27;
                while (pots < m) {
                    sb.append(valorDeCaracter((int) m % pots));
                    m -= m % pots;
                    pots *= 27;
                }
                pots /= 27;
                sb.append(valorDeCaracter((int) m / pots));
                out.print(sb.reverse());
                suma = 0;
            }
        }
        out.println();
        out.close();
    }

    private int valorDeCaracter(char c) {
        if (c <= 'N')
            return c - 'A';
        if (c == 'Ñ')
            return 'N' + 1 - 'A';
        return c + 1 - 'A';
    }

    private char valorDeCaracter(int c) {
        c += 'A';
        if (c <= 'N')
            return (char) c;
        if (c == 'O')
            return 'Ñ';
        return (char) (c - 1);
    }

    private int[] factorizaciones(int n) {
        int[] primos = primos(1000);
        for (int i = 0; i < primos.length; i++) {
            if (n % primos[i] == 0)
                return new int[]{primos[i], n / primos[i]};
        }
        return null;
    }

    private int[] primos(int M) {
        boolean b[] = new boolean[M];
        int i, j, k, c = 2;
        for (i = 2; (k = i * i) < M; i++)
            if (!b[i])
                for (j = k; j < M; j += i)
                    if (!b[j]) {
                        b[j] = true;
                        c++;
                    }
        int r[] = new int[M - c];
        for (i = 2, j = 0; i < M; i++)
            if (!b[i])
                r[j++] = i;
        return r;
    }

    private long[] gcdExtendido(long a, long b) {
        boolean bs = a < b;
        long xAnt = 1, yAnt = 0, x = 0, y = 1;
        if (bs) {
            long tmp = a;
            a = b;
            b = tmp;
        }
        while (b != 0) {
            long q = a / b, r = a % b, xTmp = xAnt - q * x, yTmp = yAnt - q * y;
            a = b;
            b = r;
            xAnt = x;
            yAnt = y;
            x = xTmp;
            y = yTmp;
        }
        return new long[]{a, bs ? yAnt : xAnt, bs ? xAnt : yAnt};
    }

    private List<String> segmentarCadena(String cadena, int longitudMaxima) {
        List<String> cadenas = new ArrayList<String>();
        int index = 0;
        while (index < cadena.length()) {
            cadenas.add(cadena.substring(index, Math.min(index + longitudMaxima, cadena.length())));
            index += longitudMaxima;
        }
        return cadenas;
    }
}
