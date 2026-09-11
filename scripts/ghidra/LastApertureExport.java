// Controller-owned Ghidra post-script for the fixed Last Aperture static profile.
// The target is imported for static analysis only; this script never executes it.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LastApertureExport extends GhidraScript {
    private static final String PROFILE_ID = "ghidra-headless-fixed-export-v1";
    private static final String EXPORT_KIND = "red-team-audit/ghidra-static-export";

    private static final int MAX_FUNCTIONS = 20_000;
    private static final int MAX_TEXT_CHARS = 512;
    private static final int MAX_EXTERNAL_FUNCTIONS_SCANNED = 100_000;
    private static final int MAX_NETWORK_IMPORTS = 512;
    private static final int MAX_REFERENCES_SCANNED_PER_IMPORT = 4_096;
    private static final int MAX_REFERENCES_PER_IMPORT = 128;
    private static final int MAX_STRING_RECORDS_SCANNED = 100_000;
    private static final int MAX_STRING_CHARS_SCANNED = 16_384;
    private static final int MAX_URLS_PER_STRING = 16;
    private static final int MAX_URL_CANDIDATE_CHARS = 2_048;
    private static final int MAX_ENDPOINTS = 512;
    private static final int MAX_AUTH_HINTS = 512;
    private static final int MAX_SOURCE_OFFSETS_PER_OBSERVATION = 16;
    private static final int MAX_PATH_SEGMENTS = 32;
    private static final int MAX_QUERY_NAMES = 32;

    private static final Pattern ABSOLUTE_HTTP_URL = Pattern.compile(
        "(?i)https?://[^\\s\\\"'<>\\u0000-\\u001f]+"
    );
    private static final Pattern SAFE_HOST = Pattern.compile("[A-Za-z0-9.:-]{1,253}");
    private static final Pattern SAFE_PATH_SEGMENT = Pattern.compile(
        "[A-Za-z][A-Za-z0-9._~-]{0,63}"
    );
    private static final Pattern SAFE_QUERY_NAME = Pattern.compile(
        "[A-Za-z][A-Za-z0-9._~-]{0,63}"
    );
    private static final Pattern UUID_SEGMENT = Pattern.compile(
        "(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    );
    private static final Pattern HEX_IDENTIFIER_SEGMENT = Pattern.compile("(?i)[0-9a-f]{8,}");
    private static final Pattern DECIMAL_IDENTIFIER_SEGMENT = Pattern.compile("[0-9]+");
    private static final Pattern JWT_LIKE_SEGMENT = Pattern.compile(
        "(?i)eyj[A-Za-z0-9_-]{12,}(?:\\.[A-Za-z0-9_-]{8,}){1,2}"
    );
    private static final Pattern OPAQUE_NAME = Pattern.compile(
        "(?=.{24,}$)(?=.*[0-9_-])[A-Za-z0-9_-]+={0,2}"
    );
    private static final Pattern JWT_LIKE_NAME = Pattern.compile(
        "(?:[A-Za-z0-9_-]{6,}\\.){2}[A-Za-z0-9_-]{6,}"
    );
    private static final Set<String> STRUCTURAL_PATH_SEGMENTS = Set.of(
        "api", "auth", "callback", "login", "logout", "oauth", "session",
        "signin", "signout", "sso", "token"
    );

    private enum NetworkApi {
        POSIX_CONNECT,
        POSIX_GETADDRINFO,
        POSIX_RECV,
        POSIX_SEND,
        POSIX_SOCKET,
        LIBCURL_EASY_GETINFO,
        LIBCURL_EASY_INIT,
        LIBCURL_EASY_PERFORM,
        LIBCURL_EASY_SETOPT,
        LIBCURL_HEADER_APPEND,
        OPENSSL_CONNECT,
        OPENSSL_READ,
        OPENSSL_SET_SERVER_NAME,
        OPENSSL_VERIFY_RESULT,
        OPENSSL_WRITE,
        WINHTTP_CONNECT,
        WINHTTP_OPEN,
        WINHTTP_OPEN_REQUEST,
        WINHTTP_QUERY_HEADERS,
        WINHTTP_RECEIVE_RESPONSE,
        WINHTTP_SEND_REQUEST,
        WINHTTP_SET_CREDENTIALS,
        WINHTTP_SET_OPTION,
        WININET_CONNECT,
        WININET_GET_COOKIE,
        WININET_OPEN,
        WININET_OPEN_REQUEST,
        WININET_QUERY_INFO,
        WININET_READ,
        WININET_SEND_REQUEST,
        WININET_SET_COOKIE,
        WINDOWS_CREDENTIAL_READ,
        WINDOWS_SSPI_ACQUIRE_CREDENTIALS,
        WINDOWS_SSPI_INITIALIZE_CONTEXT
    }

    private enum AuthHint {
        API_KEY_IDENTIFIER,
        AUTHORIZATION_HEADER_NAME,
        BASIC_SCHEME,
        BEARER_SCHEME,
        COOKIE_HEADER_NAME,
        CSRF_IDENTIFIER,
        OAUTH_ACCESS_TOKEN_PARAMETER,
        OAUTH_CLIENT_CREDENTIALS,
        OAUTH_FLOW,
        OAUTH_PKCE,
        OAUTH_REFRESH_TOKEN_PARAMETER,
        OPENID_CONNECT,
        PASSWORD_FIELD_IDENTIFIER,
        SAML_FLOW,
        SESSION_IDENTIFIER,
        SET_COOKIE_HEADER_NAME,
        URL_USERINFO_CREDENTIALS,
        USERNAME_FIELD_IDENTIFIER,
        WWW_AUTHENTICATE_HEADER_NAME
    }

    private static final class ReferenceObservation {
        private final String fromOffset;
        private final String kind;

        private ReferenceObservation(String fromOffset, String kind) {
            this.fromOffset = fromOffset;
            this.kind = kind;
        }
    }

    private static final class NetworkImportObservation {
        private final NetworkApi api;
        private final List<ReferenceObservation> references = new ArrayList<>();
        private int referencesScanned;
        private boolean referencesTruncated;

        private NetworkImportObservation(NetworkApi api) {
            this.api = api;
        }
    }

    private static final class NetworkScanResult {
        private final List<NetworkImportObservation> imports = new ArrayList<>();
        private int externalFunctionsScanned;
        private int matchingImports;
        private boolean externalFunctionsTruncated;
        private boolean importsTruncated;
    }

    private static final class PathTemplate {
        private final String value;
        private final boolean truncated;
        private final boolean valuesRedacted;

        private PathTemplate(String value, boolean truncated, boolean valuesRedacted) {
            this.value = value;
            this.truncated = truncated;
            this.valuesRedacted = valuesRedacted;
        }
    }

    private static final class EndpointObservation {
        private final String scheme;
        private final String origin;
        private final String host;
        private final int port;
        private final String pathTemplate;
        private final List<String> queryNames;
        private final List<String> sourceOffsets = new ArrayList<>();
        private final boolean userInfoPresent;
        private final boolean candidateTruncated;
        private final boolean pathTruncated;
        private final boolean pathValuesRedacted;
        private final boolean queryNamesTruncated;

        private EndpointObservation(
            String scheme,
            String origin,
            String host,
            int port,
            String pathTemplate,
            List<String> queryNames,
            String sourceOffset,
            boolean userInfoPresent,
            boolean candidateTruncated,
            boolean pathTruncated,
            boolean pathValuesRedacted,
            boolean queryNamesTruncated
        ) {
            this.scheme = scheme;
            this.origin = origin;
            this.host = host;
            this.port = port;
            this.pathTemplate = pathTemplate;
            this.queryNames = queryNames;
            this.userInfoPresent = userInfoPresent;
            this.candidateTruncated = candidateTruncated;
            this.pathTruncated = pathTruncated;
            this.pathValuesRedacted = pathValuesRedacted;
            this.queryNamesTruncated = queryNamesTruncated;
            addSourceOffset(sourceOffset);
        }

        private void addSourceOffset(String sourceOffset) {
            if (
                sourceOffset != null
                && sourceOffsets.size() < MAX_SOURCE_OFFSETS_PER_OBSERVATION
                && !sourceOffsets.contains(sourceOffset)
            ) {
                sourceOffsets.add(sourceOffset);
            }
        }
    }

    private static final class AuthHintObservation {
        private final AuthHint hint;
        private final String sourceOffset;

        private AuthHintObservation(AuthHint hint, String sourceOffset) {
            this.hint = hint;
            this.sourceOffset = sourceOffset;
        }
    }

    private static final class StringScanResult {
        private final Map<String, EndpointObservation> endpointMap = new LinkedHashMap<>();
        private final List<AuthHintObservation> authHints = new ArrayList<>();
        private final Set<String> authHintKeys = new LinkedHashSet<>();
        private int stringRecordsScanned;
        private int stringValuesScanned;
        private int truncatedStringValues;
        private int endpointCandidates;
        private int authHintCandidates;
        private boolean stringRecordsTruncated;
        private boolean endpointsTruncated;
        private boolean authHintsTruncated;
    }

    private static final class QueryNames {
        private final List<String> values;
        private final boolean truncated;

        private QueryNames(List<String> values, boolean truncated) {
            this.values = values;
            this.truncated = truncated;
        }
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("The fixed exporter requires one imported program");
        }

        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("The fixed exporter accepts exactly one output path");
        }

        Path output = Paths.get(arguments[0]).normalize();
        if (!output.isAbsolute()) {
            throw new IllegalArgumentException("The exporter output path must be absolute");
        }
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The exporter output directory must already exist");
        }
        if (Files.isSymbolicLink(output) || Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("The exporter refuses to replace an existing output");
        }

        try (BufferedWriter writer = Files.newBufferedWriter(
            output,
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE
        )) {
            writeExport(writer);
        }

        println("Last Aperture Ghidra observations export complete");
    }

    private void writeExport(BufferedWriter writer) throws Exception {
        int availableFunctions = currentProgram.getFunctionManager().getFunctionCount();
        NetworkScanResult networkScan = scanNetworkImports();
        StringScanResult stringScan = scanDefinedStrings();

        writer.write("{");
        writeStringField(writer, "schema_version", "1.0.0", true);
        writeStringField(writer, "kind", EXPORT_KIND, true);
        writeStringField(writer, "profile_id", PROFILE_ID, true);
        writeStringField(writer, "analysis_status", "OBSERVATIONS_ONLY", true);
        writeStringField(writer, "target_execution", "NOT_PERFORMED", true);

        writer.write("\"program\":{");
        writeStringField(writer, "executable_format", currentProgram.getExecutableFormat(), true);
        writeStringField(writer, "executable_sha256", currentProgram.getExecutableSHA256(), true);
        writeStringField(
            writer,
            "language_id",
            currentProgram.getLanguageID().getIdAsString(),
            true
        );
        writeStringField(
            writer,
            "compiler_spec_id",
            currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            true
        );
        writeStringField(writer, "image_base", currentProgram.getImageBase().toString(), true);
        writeStringField(writer, "minimum_address", currentProgram.getMinAddress().toString(), true);
        writeStringField(writer, "maximum_address", currentProgram.getMaxAddress().toString(), false);
        writer.write("},");

        writer.write("\"functions\":[");
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int emittedFunctions = 0;
        while (functions.hasNext() && emittedFunctions < MAX_FUNCTIONS) {
            monitor.checkCancelled();
            Function function = functions.next();
            if (emittedFunctions > 0) writer.write(",");
            writeFunction(writer, function);
            emittedFunctions += 1;
        }
        writer.write("],");

        writeNetworkImports(writer, networkScan);
        writer.write(",");
        writeEndpointObservations(writer, stringScan);
        writer.write(",");
        writeAuthHints(writer, stringScan);
        writer.write(",");

        writer.write("\"coverage\":{");
        writeNumberField(writer, "function_limit", MAX_FUNCTIONS, true);
        writeNumberField(writer, "available_functions", availableFunctions, true);
        writeNumberField(writer, "emitted_functions", emittedFunctions, true);
        writeBooleanField(writer, "truncated", functions.hasNext(), false);
        writer.write("},");

        writeProtocolCoverage(writer, networkScan, stringScan);
        writer.write("}");
    }

    private void writeFunction(BufferedWriter writer, Function function) throws IOException {
        writer.write("{");
        writeStringField(writer, "entry_point", function.getEntryPoint().toString(), true);
        writeStringField(writer, "name", function.getName(), true);
        writeBooleanField(writer, "external", function.isExternal(), true);
        writeBooleanField(writer, "thunk", function.isThunk(), true);
        writeNumberField(writer, "body_address_count", function.getBody().getNumAddresses(), false);
        writer.write("}");
    }

    private NetworkScanResult scanNetworkImports() throws Exception {
        NetworkScanResult result = new NetworkScanResult();
        FunctionIterator functions = currentProgram.getFunctionManager().getExternalFunctions();
        while (
            functions.hasNext()
            && result.externalFunctionsScanned < MAX_EXTERNAL_FUNCTIONS_SCANNED
        ) {
            monitor.checkCancelled();
            Function function = functions.next();
            result.externalFunctionsScanned += 1;
            NetworkApi api = classifyNetworkApi(function.getName());
            if (api == null) continue;
            result.matchingImports += 1;
            if (result.imports.size() >= MAX_NETWORK_IMPORTS) {
                result.importsTruncated = true;
                continue;
            }
            NetworkImportObservation observation = new NetworkImportObservation(api);
            collectReferences(function, observation);
            result.imports.add(observation);
        }
        result.externalFunctionsTruncated = functions.hasNext();
        if (result.externalFunctionsTruncated) result.importsTruncated = true;
        return result;
    }

    private void collectReferences(
        Function function,
        NetworkImportObservation observation
    ) throws Exception {
        ReferenceIterator references = currentProgram
            .getReferenceManager()
            .getReferencesTo(function.getEntryPoint());
        Set<String> emitted = new LinkedHashSet<>();
        while (
            references.hasNext()
            && observation.referencesScanned < MAX_REFERENCES_SCANNED_PER_IMPORT
        ) {
            monitor.checkCancelled();
            Reference reference = references.next();
            observation.referencesScanned += 1;
            String fromOffset = imageRelativeOffset(reference.getFromAddress());
            if (fromOffset == null) continue;
            String kind = reference.getReferenceType().isCall()
                ? "CALL"
                : reference.getReferenceType().isData() ? "DATA" : "OTHER";
            String key = kind + ":" + fromOffset;
            if (!emitted.add(key)) continue;
            if (observation.references.size() >= MAX_REFERENCES_PER_IMPORT) {
                observation.referencesTruncated = true;
                continue;
            }
            observation.references.add(new ReferenceObservation(fromOffset, kind));
        }
        if (references.hasNext()) observation.referencesTruncated = true;
    }

    private NetworkApi classifyNetworkApi(String rawName) {
        if (rawName == null) return null;
        String name = rawName.toLowerCase(Locale.ROOT);
        while (name.startsWith("_")) name = name.substring(1);
        if (name.startsWith("imp_")) name = name.substring(4);
        name = name.replaceFirst("@[0-9]+$", "");

        switch (name) {
            case "socket": return NetworkApi.POSIX_SOCKET;
            case "connect": return NetworkApi.POSIX_CONNECT;
            case "send": return NetworkApi.POSIX_SEND;
            case "recv": return NetworkApi.POSIX_RECV;
            case "getaddrinfo": return NetworkApi.POSIX_GETADDRINFO;
            case "curl_easy_init": return NetworkApi.LIBCURL_EASY_INIT;
            case "curl_easy_setopt": return NetworkApi.LIBCURL_EASY_SETOPT;
            case "curl_easy_perform": return NetworkApi.LIBCURL_EASY_PERFORM;
            case "curl_easy_getinfo": return NetworkApi.LIBCURL_EASY_GETINFO;
            case "curl_slist_append": return NetworkApi.LIBCURL_HEADER_APPEND;
            case "ssl_connect": return NetworkApi.OPENSSL_CONNECT;
            case "ssl_read": return NetworkApi.OPENSSL_READ;
            case "ssl_write": return NetworkApi.OPENSSL_WRITE;
            case "ssl_get_verify_result": return NetworkApi.OPENSSL_VERIFY_RESULT;
            case "ssl_set_tlsext_host_name": return NetworkApi.OPENSSL_SET_SERVER_NAME;
            case "winhttpopen": return NetworkApi.WINHTTP_OPEN;
            case "winhttpconnect": return NetworkApi.WINHTTP_CONNECT;
            case "winhttpopenrequest": return NetworkApi.WINHTTP_OPEN_REQUEST;
            case "winhttpsendrequest": return NetworkApi.WINHTTP_SEND_REQUEST;
            case "winhttpreceiveresponse": return NetworkApi.WINHTTP_RECEIVE_RESPONSE;
            case "winhttpqueryheaders": return NetworkApi.WINHTTP_QUERY_HEADERS;
            case "winhttpsetcredentials": return NetworkApi.WINHTTP_SET_CREDENTIALS;
            case "winhttpsetoption": return NetworkApi.WINHTTP_SET_OPTION;
            case "internetopena":
            case "internetopenw": return NetworkApi.WININET_OPEN;
            case "internetconnecta":
            case "internetconnectw": return NetworkApi.WININET_CONNECT;
            case "httpopenrequesta":
            case "httpopenrequestw": return NetworkApi.WININET_OPEN_REQUEST;
            case "httpsendrequesta":
            case "httpsendrequestw": return NetworkApi.WININET_SEND_REQUEST;
            case "httpqueryinfoa":
            case "httpqueryinfow": return NetworkApi.WININET_QUERY_INFO;
            case "internetreadfile": return NetworkApi.WININET_READ;
            case "internetgetcookiea":
            case "internetgetcookiew": return NetworkApi.WININET_GET_COOKIE;
            case "internetsetcookiea":
            case "internetsetcookiew": return NetworkApi.WININET_SET_COOKIE;
            case "credreada":
            case "credreadw": return NetworkApi.WINDOWS_CREDENTIAL_READ;
            case "acquirecredentialshandlea":
            case "acquirecredentialshandlew":
                return NetworkApi.WINDOWS_SSPI_ACQUIRE_CREDENTIALS;
            case "initializesecuritycontexta":
            case "initializesecuritycontextw":
                return NetworkApi.WINDOWS_SSPI_INITIALIZE_CONTEXT;
            default: return null;
        }
    }

    private StringScanResult scanDefinedStrings() throws Exception {
        StringScanResult result = new StringScanResult();
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        while (
            dataIterator.hasNext()
            && result.stringRecordsScanned < MAX_STRING_RECORDS_SCANNED
        ) {
            monitor.checkCancelled();
            Data data = dataIterator.next();
            result.stringRecordsScanned += 1;
            if (!data.hasStringValue()) continue;
            Object value = data.getValue();
            if (!(value instanceof String)) continue;
            result.stringValuesScanned += 1;
            String stringValue = (String) value;
            if (stringValue.length() > MAX_STRING_CHARS_SCANNED) {
                result.truncatedStringValues += 1;
                stringValue = stringValue.substring(0, MAX_STRING_CHARS_SCANNED);
            }
            String sourceOffset = imageRelativeOffset(data.getAddress());
            scanAuthHints(stringValue, sourceOffset, result);
            scanEndpoints(stringValue, sourceOffset, result);
        }
        result.stringRecordsTruncated = dataIterator.hasNext();
        if (result.stringRecordsTruncated || result.truncatedStringValues > 0) {
            result.endpointsTruncated = true;
            result.authHintsTruncated = true;
        }
        return result;
    }

    private void scanEndpoints(
        String stringValue,
        String sourceOffset,
        StringScanResult result
    ) {
        Matcher matcher = ABSOLUTE_HTTP_URL.matcher(stringValue);
        int matchesInString = 0;
        while (matchesInString < MAX_URLS_PER_STRING && matcher.find()) {
            matchesInString += 1;
            result.endpointCandidates += 1;
            String candidate = stripUrlTrailingPunctuation(matcher.group());
            boolean candidateTruncated = candidate.length() > MAX_URL_CANDIDATE_CHARS;
            if (candidateTruncated) {
                candidate = candidate.substring(0, MAX_URL_CANDIDATE_CHARS);
                result.endpointsTruncated = true;
            }
            EndpointObservation endpoint = endpointFromCandidate(
                candidate,
                sourceOffset,
                candidateTruncated
            );
            if (endpoint == null) continue;
            if (endpoint.userInfoPresent) {
                addAuthHint(AuthHint.URL_USERINFO_CREDENTIALS, sourceOffset, result);
            }
            String key = endpoint.scheme
                + "|" + endpoint.origin
                + "|" + endpoint.pathTemplate
                + "|" + String.join(",", endpoint.queryNames);
            EndpointObservation existing = result.endpointMap.get(key);
            if (existing != null) {
                existing.addSourceOffset(sourceOffset);
            } else if (result.endpointMap.size() < MAX_ENDPOINTS) {
                result.endpointMap.put(key, endpoint);
            } else {
                result.endpointsTruncated = true;
            }
        }
        if (matcher.find()) result.endpointsTruncated = true;
    }

    private EndpointObservation endpointFromCandidate(
        String candidate,
        String sourceOffset,
        boolean candidateTruncated
    ) {
        try {
            URI uri = new URI(candidate);
            String scheme = uri.getScheme();
            if (scheme == null) return null;
            scheme = scheme.toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) return null;
            String host = uri.getHost();
            if (host == null || !SAFE_HOST.matcher(host).matches()) return null;
            host = host.toLowerCase(Locale.ROOT);
            int explicitPort = uri.getPort();
            if (explicitPort > 65_535) return null;
            int defaultPort = scheme.equals("https") ? 443 : 80;
            int effectivePort = explicitPort >= 0 ? explicitPort : defaultPort;
            String originHost = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
            String origin = scheme + "://" + originHost;
            if (explicitPort >= 0 && explicitPort != defaultPort) origin += ":" + explicitPort;

            PathTemplate path = templatePath(uri.getRawPath());
            QueryNames queryNames = queryNames(uri.getRawQuery());
            return new EndpointObservation(
                scheme,
                origin,
                host,
                effectivePort,
                path.value,
                queryNames.values,
                sourceOffset,
                uri.getRawUserInfo() != null,
                candidateTruncated,
                path.truncated,
                path.valuesRedacted,
                queryNames.truncated
            );
        } catch (URISyntaxException | IllegalArgumentException ignored) {
            return null;
        }
    }

    private PathTemplate templatePath(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return new PathTemplate("/", false, false);
        }
        String[] rawSegments = rawPath.split("/", -1);
        StringBuilder template = new StringBuilder();
        boolean truncated = false;
        boolean valuesRedacted = false;
        int segmentCount = 0;
        for (int index = 1; index < rawSegments.length; index += 1) {
            if (segmentCount >= MAX_PATH_SEGMENTS) {
                template.append("/{...}");
                truncated = true;
                break;
            }
            String segment = rawSegments[index];
            template.append("/");
            if (!segment.isEmpty()) {
                int matrixIndex = segment.indexOf(';');
                if (matrixIndex >= 0) {
                    segment = segment.substring(0, matrixIndex);
                    valuesRedacted = true;
                }
                String templated = templateSegment(segment);
                template.append(templated);
                valuesRedacted |= !templated.equals(segment);
            }
            segmentCount += 1;
            if (template.length() >= MAX_TEXT_CHARS) {
                template.setLength(MAX_TEXT_CHARS - 6);
                template.append("{...}");
                truncated = true;
                break;
            }
        }
        return new PathTemplate(
            template.length() == 0 ? "/" : template.toString(),
            truncated,
            valuesRedacted
        );
    }

    private String templateSegment(String segment) {
        if (DECIMAL_IDENTIFIER_SEGMENT.matcher(segment).matches()) return "{integer}";
        if (UUID_SEGMENT.matcher(segment).matches()) return "{uuid}";
        if (HEX_IDENTIFIER_SEGMENT.matcher(segment).matches()) return "{hex}";
        if (
            JWT_LIKE_SEGMENT.matcher(segment).matches()
            || segment.indexOf('%') >= 0
            || segment.indexOf('@') >= 0
        ) return "{value}";
        String lower = segment.toLowerCase(Locale.ROOT);
        if (
            SAFE_PATH_SEGMENT.matcher(segment).matches()
            && (STRUCTURAL_PATH_SEGMENTS.contains(lower) || lower.matches("v[0-9]+"))
        ) return segment;
        return "{segment}";
    }

    private QueryNames queryNames(String rawQuery) {
        List<String> names = new ArrayList<>();
        Set<String> unique = new LinkedHashSet<>();
        boolean truncated = false;
        if (rawQuery == null || rawQuery.isEmpty()) return new QueryNames(names, false);

        String[] queryParts = rawQuery.split("[&;]", -1);
        for (String queryPart : queryParts) {
            int equalsIndex = queryPart.indexOf('=');
            String queryName = equalsIndex >= 0
                ? queryPart.substring(0, equalsIndex)
                : queryPart;
            if (!SAFE_QUERY_NAME.matcher(queryName).matches()) {
                continue;
            }
            if (
                HEX_IDENTIFIER_SEGMENT.matcher(queryName).matches()
                || OPAQUE_NAME.matcher(queryName).matches()
                || JWT_LIKE_NAME.matcher(queryName).matches()
            ) queryName = "redacted_name";
            if (!unique.add(queryName)) continue;
            if (names.size() >= MAX_QUERY_NAMES) {
                truncated = true;
                continue;
            }
            names.add(queryName);
        }
        return new QueryNames(names, truncated);
    }

    private void scanAuthHints(
        String stringValue,
        String sourceOffset,
        StringScanResult result
    ) {
        String lower = stringValue.toLowerCase(Locale.ROOT);
        EnumSet<AuthHint> hints = EnumSet.noneOf(AuthHint.class);
        if (lower.contains("authorization")) hints.add(AuthHint.AUTHORIZATION_HEADER_NAME);
        if (lower.contains("www-authenticate")) hints.add(AuthHint.WWW_AUTHENTICATE_HEADER_NAME);
        if (lower.contains("set-cookie")) hints.add(AuthHint.SET_COOKIE_HEADER_NAME);
        if (lower.contains("cookie:") || lower.equals("cookie")) hints.add(AuthHint.COOKIE_HEADER_NAME);
        if (lower.contains("bearer ") || lower.equals("bearer")) hints.add(AuthHint.BEARER_SCHEME);
        if (lower.contains("basic ") || lower.equals("basic")) hints.add(AuthHint.BASIC_SCHEME);
        if (lower.contains("oauth") || lower.contains("/token")) hints.add(AuthHint.OAUTH_FLOW);
        if (lower.contains("access_token")) hints.add(AuthHint.OAUTH_ACCESS_TOKEN_PARAMETER);
        if (lower.contains("refresh_token")) hints.add(AuthHint.OAUTH_REFRESH_TOKEN_PARAMETER);
        if (lower.contains("client_secret") || lower.contains("client_credentials")) {
            hints.add(AuthHint.OAUTH_CLIENT_CREDENTIALS);
        }
        if (lower.contains("code_challenge") || lower.contains("code_verifier")) {
            hints.add(AuthHint.OAUTH_PKCE);
        }
        if (lower.contains("openid") || lower.contains("oidc")) hints.add(AuthHint.OPENID_CONNECT);
        if (lower.contains("saml")) hints.add(AuthHint.SAML_FLOW);
        if (lower.contains("x-api-key") || lower.contains("api_key") || lower.contains("apikey")) {
            hints.add(AuthHint.API_KEY_IDENTIFIER);
        }
        if (lower.contains("csrf") || lower.contains("xsrf")) hints.add(AuthHint.CSRF_IDENTIFIER);
        if (
            lower.contains("sessionid")
            || lower.contains("session_id")
            || lower.contains("sessioncookie")
        ) {
            hints.add(AuthHint.SESSION_IDENTIFIER);
        }
        if (lower.contains("password") || lower.contains("passwd")) {
            hints.add(AuthHint.PASSWORD_FIELD_IDENTIFIER);
        }
        if (lower.contains("username") || lower.contains("user_name")) {
            hints.add(AuthHint.USERNAME_FIELD_IDENTIFIER);
        }
        for (AuthHint hint : hints) addAuthHint(hint, sourceOffset, result);
    }

    private void addAuthHint(
        AuthHint hint,
        String sourceOffset,
        StringScanResult result
    ) {
        result.authHintCandidates += 1;
        String key = hint.name() + "|" + (sourceOffset == null ? "" : sourceOffset);
        if (!result.authHintKeys.add(key)) return;
        if (result.authHints.size() >= MAX_AUTH_HINTS) {
            result.authHintsTruncated = true;
            return;
        }
        result.authHints.add(new AuthHintObservation(hint, sourceOffset));
    }

    private String stripUrlTrailingPunctuation(String value) {
        int end = value.length();
        while (end > 0) {
            char character = value.charAt(end - 1);
            if (
                character == '.'
                || character == ','
                || character == ')'
                || character == ']'
                || character == '}'
            ) {
                end -= 1;
            } else {
                break;
            }
        }
        return value.substring(0, end);
    }

    private String imageRelativeOffset(Address address) {
        if (address == null) return null;
        Address imageBase = currentProgram.getImageBase();
        if (
            !address.getAddressSpace().equals(imageBase.getAddressSpace())
            || address.compareTo(imageBase) < 0
        ) {
            return null;
        }
        try {
            long offset = address.subtract(imageBase);
            return "0x" + Long.toUnsignedString(offset, 16);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private void writeNetworkImports(
        BufferedWriter writer,
        NetworkScanResult result
    ) throws IOException {
        writer.write("\"network_imports\":[");
        for (int index = 0; index < result.imports.size(); index += 1) {
            if (index > 0) writer.write(",");
            NetworkImportObservation observation = result.imports.get(index);
            writer.write("{");
            writeStringField(writer, "api", observation.api.name(), true);
            writer.write("\"references\":[");
            for (
                int referenceIndex = 0;
                referenceIndex < observation.references.size();
                referenceIndex += 1
            ) {
                if (referenceIndex > 0) writer.write(",");
                ReferenceObservation reference = observation.references.get(referenceIndex);
                writer.write("{");
                writeStringField(writer, "from_offset", reference.fromOffset, true);
                writeStringField(writer, "kind", reference.kind, false);
                writer.write("}");
            }
            writer.write("],");
            writer.write("\"callsite_offsets\":[");
            boolean wroteCallsite = false;
            for (ReferenceObservation reference : observation.references) {
                if (!reference.kind.equals("CALL")) continue;
                if (wroteCallsite) writer.write(",");
                writeJsonString(writer, reference.fromOffset);
                wroteCallsite = true;
            }
            writer.write("],");
            writeNumberField(writer, "references_scanned", observation.referencesScanned, true);
            writeBooleanField(writer, "references_truncated", observation.referencesTruncated, false);
            writer.write("}");
        }
        writer.write("]");
    }

    private void writeEndpointObservations(
        BufferedWriter writer,
        StringScanResult result
    ) throws IOException {
        writer.write("\"endpoint_observations\":[");
        int index = 0;
        for (EndpointObservation endpoint : result.endpointMap.values()) {
            if (index > 0) writer.write(",");
            writer.write("{");
            writeStringField(writer, "scheme", endpoint.scheme, true);
            writeStringField(writer, "origin", endpoint.origin, true);
            writeStringField(writer, "host", endpoint.host, true);
            writeNumberField(writer, "port", endpoint.port, true);
            writeStringField(writer, "path_template", endpoint.pathTemplate, true);
            writeStringArrayField(writer, "query_names", endpoint.queryNames, true);
            writeStringArrayField(writer, "source_offsets", endpoint.sourceOffsets, true);
            writeBooleanField(writer, "userinfo_present", endpoint.userInfoPresent, true);
            writeBooleanField(writer, "candidate_truncated", endpoint.candidateTruncated, true);
            writeBooleanField(writer, "path_truncated", endpoint.pathTruncated, true);
            writeBooleanField(writer, "path_values_redacted", endpoint.pathValuesRedacted, true);
            writeBooleanField(writer, "query_names_truncated", endpoint.queryNamesTruncated, false);
            writer.write("}");
            index += 1;
        }
        writer.write("]");
    }

    private void writeAuthHints(
        BufferedWriter writer,
        StringScanResult result
    ) throws IOException {
        writer.write("\"auth_hints\":[");
        for (int index = 0; index < result.authHints.size(); index += 1) {
            if (index > 0) writer.write(",");
            AuthHintObservation observation = result.authHints.get(index);
            writer.write("{");
            writeStringField(writer, "hint", observation.hint.name(), true);
            writeStringField(
                writer,
                "source_offset",
                observation.sourceOffset == null ? "UNMAPPED" : observation.sourceOffset,
                false
            );
            writer.write("}");
        }
        writer.write("]");
    }

    private void writeProtocolCoverage(
        BufferedWriter writer,
        NetworkScanResult networkScan,
        StringScanResult stringScan
    ) throws IOException {
        writer.write("\"protocol_coverage\":{");
        writeNumberField(writer, "network_import_limit", MAX_NETWORK_IMPORTS, true);
        writeNumberField(writer, "references_per_import_limit", MAX_REFERENCES_PER_IMPORT, true);
        writeNumberField(writer, "external_functions_scanned", networkScan.externalFunctionsScanned, true);
        writeNumberField(writer, "matching_network_imports", networkScan.matchingImports, true);
        writeNumberField(writer, "emitted_network_imports", networkScan.imports.size(), true);
        writeBooleanField(
            writer,
            "external_function_scan_truncated",
            networkScan.externalFunctionsTruncated,
            true
        );
        writeBooleanField(writer, "network_imports_truncated", networkScan.importsTruncated, true);
        writeNumberField(writer, "string_record_limit", MAX_STRING_RECORDS_SCANNED, true);
        writeNumberField(writer, "string_records_scanned", stringScan.stringRecordsScanned, true);
        writeNumberField(writer, "string_values_scanned", stringScan.stringValuesScanned, true);
        writeNumberField(writer, "truncated_string_values", stringScan.truncatedStringValues, true);
        writeBooleanField(writer, "string_scan_truncated", stringScan.stringRecordsTruncated, true);
        writeNumberField(writer, "endpoint_limit", MAX_ENDPOINTS, true);
        writeNumberField(writer, "endpoint_candidates", stringScan.endpointCandidates, true);
        writeNumberField(writer, "emitted_endpoints", stringScan.endpointMap.size(), true);
        writeBooleanField(writer, "endpoints_truncated", stringScan.endpointsTruncated, true);
        writeNumberField(writer, "auth_hint_limit", MAX_AUTH_HINTS, true);
        writeNumberField(writer, "auth_hint_candidates", stringScan.authHintCandidates, true);
        writeNumberField(writer, "emitted_auth_hints", stringScan.authHints.size(), true);
        writeBooleanField(writer, "auth_hints_truncated", stringScan.authHintsTruncated, false);
        writer.write("}");
    }

    private void writeStringArrayField(
        BufferedWriter writer,
        String key,
        List<String> values,
        boolean trailingComma
    ) throws IOException {
        writer.write("\"");
        writer.write(key);
        writer.write("\":[");
        for (int index = 0; index < values.size(); index += 1) {
            if (index > 0) writer.write(",");
            writeJsonString(writer, truncate(values.get(index)));
        }
        writer.write("]");
        if (trailingComma) writer.write(",");
    }

    private void writeStringField(
        BufferedWriter writer,
        String key,
        String value,
        boolean trailingComma
    ) throws IOException {
        writer.write("\"");
        writer.write(key);
        writer.write("\":");
        writeJsonString(writer, value == null ? "" : truncate(value));
        if (trailingComma) writer.write(",");
    }

    private void writeNumberField(
        BufferedWriter writer,
        String key,
        long value,
        boolean trailingComma
    ) throws IOException {
        writer.write("\"");
        writer.write(key);
        writer.write("\":");
        writer.write(Long.toString(value));
        if (trailingComma) writer.write(",");
    }

    private void writeBooleanField(
        BufferedWriter writer,
        String key,
        boolean value,
        boolean trailingComma
    ) throws IOException {
        writer.write("\"");
        writer.write(key);
        writer.write("\":");
        writer.write(value ? "true" : "false");
        if (trailingComma) writer.write(",");
    }

    private String truncate(String value) {
        if (value.length() <= MAX_TEXT_CHARS) return value;
        return value.substring(0, MAX_TEXT_CHARS);
    }

    private void writeJsonString(BufferedWriter writer, String value) throws IOException {
        writer.write("\"");
        for (int index = 0; index < value.length(); index += 1) {
            char character = value.charAt(index);
            switch (character) {
                case '\"':
                    writer.write("\\\"");
                    break;
                case '\\':
                    writer.write("\\\\");
                    break;
                case '\b':
                    writer.write("\\b");
                    break;
                case '\f':
                    writer.write("\\f");
                    break;
                case '\n':
                    writer.write("\\n");
                    break;
                case '\r':
                    writer.write("\\r");
                    break;
                case '\t':
                    writer.write("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        writer.write(String.format("\\u%04x", (int) character));
                    } else {
                        writer.write(character);
                    }
            }
        }
        writer.write("\"");
    }
}
