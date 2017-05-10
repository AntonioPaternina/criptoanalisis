package co.edu.poli.seguridad.informacion.criptoanalisis.cli;

import co.edu.poli.seguridad.informacion.criptoanalisis.Criptografia;
import org.apache.commons.cli.*;
import org.apache.sanselan.ImageReadException;
import org.apache.sanselan.ImageWriteException;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class InterfazCLI {

    public static void main(String args[]) throws ParseException, IOException, ImageWriteException, ImageReadException {
        Options opciones = construirOpciones();
        CommandLineParser commandLineParser = new DefaultParser();
        CommandLine commandLine = commandLineParser.parse(opciones, args);


        if (validarArgumentos(opciones, commandLine)) {
            procesarComando(commandLine);
        }
    }

    private static void procesarComando(CommandLine commandLine) throws IOException, ImageWriteException,
            ImageReadException {

        int e = Integer.parseInt(commandLine.getOptionValue("e"));
        int n = Integer.parseInt(commandLine.getOptionValue("n"));
        String t = commandLine.getOptionValue("t");
        int s = Integer.parseInt(commandLine.getOptionValue("s"));
        char cifrando;
        if (commandLine.hasOption("c")) {
            cifrando = 'c';
        } else {
            cifrando = 'd';
        }

        Criptografia criptografia = new Criptografia(e, n, t, s, cifrando);
        if (commandLine.hasOption("a")) {
            criptografia.ejecutar2();
        } else {
            criptografia.ejecutar();
        }
    }

    private static boolean validarArgumentos(Options opciones, CommandLine commandLine) {
        boolean valido = (commandLine.hasOption("c") || commandLine.hasOption("d")) && commandLine.hasOption("e") &&
                commandLine.hasOption("n") && commandLine.hasOption("t") && commandLine.hasOption("s");
        if (!valido) {
            imprimirAyuda(opciones, 80, "Ayuda Utilidad Criptoanálisis", "Fin de la ayuda",
                    5, 3, true, System.out);
            return false;
        }

        return true;
    }

    public static Options construirOpciones() {
        final Options opciones = new Options();
        opciones.addOption("c", "cifrar", false, "cifrar mensaje")
                .addOption("d", "descifrar", false, "descifrar mensaje")
                .addOption("e", "encryption", true, "valor e de la llave pública")
                .addOption("n", "modulo", true, "el valor de n de la llave pública")
                .addOption("t", "texto", true, "texto a procesar")
                .addOption("s", "segmentos", true, "número de segmentos")
                .addOption("a", "algoritmo-alternativo", false, "algoritmo alternativo")
        ;

        return opciones;
    }

    public static void imprimirAyuda(final Options opciones, final int anchoFila, final String encabezado, final
    String pie, final int espaciosAntesDeLaOpcion, final int espaciosAntesDeLaDescripcionDeLaOpcion, final boolean
                                             mostrarUso,
                                     final OutputStream out) {
        final String commandLineSyntax = "java -jar criptoanalisis.jar";
        final PrintWriter writer = new PrintWriter(out);
        final HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp(
                writer,
                anchoFila,
                commandLineSyntax,
                encabezado,
                opciones,
                espaciosAntesDeLaOpcion,
                espaciosAntesDeLaDescripcionDeLaOpcion,
                pie,
                mostrarUso);
        writer.flush();
    }
}