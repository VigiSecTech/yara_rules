import java.io.*;
import java.nio.file.*;
import java.util.*;

public class YaraRuleChecker {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java YaraRuleChecker <directory>");
            System.exit(1);
        }

        Path rootDir = Paths.get(args[0]);
        if (!Files.exists(rootDir) || !Files.isDirectory(rootDir)) {
            System.err.println("Directory does not exist or is not accessible: " + rootDir);
            System.exit(1);
        }

        try {
            List<Path> yarFiles = findYarFiles(rootDir);
            System.err.println("[DEBUG] Found " + yarFiles.size() + " .yar files.");
            for (Path file : yarFiles) {
                boolean isValid = isYaraFileValid(file);
                if (isValid) {
                    System.out.println("include \"" + file + "\"");
                }
            }
        } catch (IOException e) {
            System.err.println("Error while scanning directories: " + e.getMessage());
            System.exit(1);
        }
    }

    private static List<Path> findYarFiles(Path rootDir) throws IOException {
        List<Path> result = new ArrayList<>();
        Files.walk(rootDir)
             .filter(path -> path.toString().endsWith(".yar"))
             .forEach(result::add);
        return result;
    }

    private static boolean isYaraFileValid(Path filePath) {
        try {
            // Отладка: выводим выполняемую команду
            List<String> cmd = List.of("yr", "scan", filePath.toString(), ".");
//            System.err.println("[DEBUG] Executing command: " + String.join(" ", cmd));

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true); // объединяем stdout и stderr
            Process process = pb.start();

            // Читаем вывод команды для отладки
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
//                System.err.println("[OUTPUT] " + line);
            }

            int exitCode = process.waitFor();
//            System.err.println("[DEBUG] Command exited with code: " + exitCode);

            // Возвращаем true, если exit code НЕ равен 1
            // (в YARA 0 — успех, 1 — нет совпадений)
            return exitCode != 1;

        } catch (Exception e) {
            System.err.println("[ERROR] Error executing 'yr scan' on file: " + filePath);
            e.printStackTrace();
            return false;
        }
    }
}
