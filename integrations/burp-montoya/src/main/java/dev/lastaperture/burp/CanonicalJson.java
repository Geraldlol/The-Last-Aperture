package dev.lastaperture.burp;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** Minimal canonical JSON encoder for the extension's value-free export. */
final class CanonicalJson {
    private CanonicalJson() {}

    static String encode(Object value) {
        StringBuilder out = new StringBuilder();
        append(out, value);
        return out.toString();
    }

    private static void append(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            appendString(out, text);
        } else if (value instanceof Boolean || value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            appendMap(out, map);
        } else if (value instanceof Iterable<?> values) {
            appendIterable(out, values);
        } else if (value.getClass().isArray()) {
            List<Object> values = new ArrayList<>(Array.getLength(value));
            for (int i = 0; i < Array.getLength(value); i += 1) {
                values.add(Array.get(value, i));
            }
            appendIterable(out, values);
        } else {
            throw new IllegalArgumentException("unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void appendMap(StringBuilder out, Map<?, ?> map) {
        List<Map.Entry<?, ?>> entries = new ArrayList<>(map.entrySet());
        entries.sort(Comparator.comparing(entry -> requireStringKey(entry.getKey())));
        out.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> entry : entries) {
            if (!first) out.append(',');
            first = false;
            appendString(out, requireStringKey(entry.getKey()));
            out.append(':');
            append(out, entry.getValue());
        }
        out.append('}');
    }

    private static String requireStringKey(Object key) {
        if (!(key instanceof String text)) {
            throw new IllegalArgumentException("JSON object keys must be strings");
        }
        return text;
    }

    private static void appendIterable(StringBuilder out, Iterable<?> values) {
        out.append('[');
        boolean first = true;
        for (Object value : values) {
            if (!first) out.append(',');
            first = false;
            append(out, value);
        }
        out.append(']');
    }

    private static void appendString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i += 1) {
            char character = value.charAt(i);
            switch (character) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (character < 0x20 || character == 0x7f
                            || (character >= 0x80 && character <= 0x9f)
                            || character == 0x2028 || character == 0x2029) {
                        out.append(String.format("\\u%04x", (int) character));
                    } else {
                        out.append(character);
                    }
                }
            }
        }
        out.append('"');
    }
}
