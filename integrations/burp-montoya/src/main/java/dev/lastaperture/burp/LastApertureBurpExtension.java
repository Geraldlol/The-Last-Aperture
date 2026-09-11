package dev.lastaperture.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

import java.util.concurrent.atomic.AtomicBoolean;

/** Community-compatible, read-only Proxy history export bridge. */
public final class LastApertureBurpExtension implements BurpExtension {
    private final AtomicBoolean closed = new AtomicBoolean();
    private ExportPanel panel;
    private Registration suiteTabRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("The Last Aperture Proxy Export");
        BurpRuntime runtime = BurpRuntime.from(api.burpSuite().version());
        panel = new ExportPanel(new ProxyHistoryExporter(api, runtime), runtime);
        api.userInterface().applyThemeToComponent(panel);
        suiteTabRegistration = api.userInterface().registerSuiteTab("Last Aperture", panel);
        api.extension().registerUnloadingHandler(this::close);
    }

    private void close() {
        if (!closed.compareAndSet(false, true)) return;
        if (panel != null) panel.close();
        if (suiteTabRegistration != null && suiteTabRegistration.isRegistered()) {
            suiteTabRegistration.deregister();
        }
    }
}
