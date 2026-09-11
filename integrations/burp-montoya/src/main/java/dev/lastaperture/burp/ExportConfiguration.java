package dev.lastaperture.burp;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

record ExportConfiguration(
        String origin,
        String pathPrefix,
        List<String> pathLiterals,
        int maxItems,
        Path output) {

    ExportConfiguration {
        origin = CaptureSanitizer.canonicalOrigin(origin);
        pathPrefix = CaptureSanitizer.normalizePathPrefix(pathPrefix);
        pathLiterals = CaptureSanitizer.normalizePathLiterals(pathLiterals);
        if (maxItems < 1 || maxItems > 10_000) {
            throw new IllegalArgumentException("maximum history records examined must be between 1 and 10000");
        }
        if (output == null || !output.isAbsolute()) {
            throw new IllegalArgumentException("output must be an absolute local path");
        }
        output = output.normalize();
        String rendered = output.toString();
        if (rendered.startsWith("\\\\") || rendered.startsWith("\\\\?\\") || rendered.startsWith("\\\\.\\")) {
            throw new IllegalArgumentException("output must be a local path, not a UNC or device path");
        }
        Path outputName = output.getFileName();
        if (outputName == null) throw new IllegalArgumentException("output must name a file");
        String filename = outputName.toString().toLowerCase();
        if (!(filename.endsWith(".har") || filename.endsWith(".json"))) {
            throw new IllegalArgumentException("output filename must end in .har or .json");
        }
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IllegalArgumentException("output parent directory must already exist");
        }
        rejectSymbolicLinks(parent);
        if (Files.exists(output)) {
            throw new IllegalArgumentException("output already exists; exports never replace files");
        }
    }

    Set<String> pathLiteralSet() {
        return Set.copyOf(new HashSet<>(pathLiterals));
    }

    private static void rejectSymbolicLinks(Path path) {
        Path current = path.getRoot();
        for (Path part : path) {
            current = current == null ? part : current.resolve(part);
            if (Files.isSymbolicLink(current)) {
                throw new IllegalArgumentException("output path must not traverse symbolic links");
            }
        }
    }
}
