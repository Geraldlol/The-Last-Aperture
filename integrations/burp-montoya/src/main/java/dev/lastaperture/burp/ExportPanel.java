package dev.lastaperture.burp;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

final class ExportPanel extends JPanel implements AutoCloseable {
    private final ProxyHistoryExporter exporter;
    private final ExecutorService worker;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean exporting = new AtomicBoolean();
    private final JTextField origin = new JTextField();
    private final JTextField pathPrefix = new JTextField("/");
    private final JTextField pathLiterals = new JTextField();
    private final JSpinner maxItems = new JSpinner(new SpinnerNumberModel(1000, 1, 10_000, 1));
    private final JTextField output = new JTextField();
    private final JButton export = new JButton("Export proxy history");
    private final JLabel status = new JLabel("Ready");

    ExportPanel(ProxyHistoryExporter exporter, BurpRuntime runtime) {
        super(new BorderLayout(8, 8));
        this.exporter = exporter;
        this.worker = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "last-aperture-burp-export");
            thread.setDaemon(true);
            return thread;
        });
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JTextArea explanation = new JTextArea(
                "Exports value-free protocol shape from existing Proxy HTTP history. "
                        + "The extension sends no requests, modifies no traffic, never calls Scanner, "
                        + "and never replaces an existing output file.\n"
                        + "Runtime: " + runtime.edition() + " / " + runtime.version());
        explanation.setEditable(false);
        explanation.setLineWrap(true);
        explanation.setWrapStyleWord(true);
        explanation.setOpaque(false);
        add(explanation, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        addRow(form, 0, "Exact origin", origin);
        addRow(form, 1, "Path prefix", pathPrefix);
        addRow(form, 2, "Literal route segments (comma separated)", pathLiterals);
        addRow(form, 3, "Maximum history records examined", maxItems);
        addRow(form, 4, "New absolute .har or .json output", output);
        add(form, BorderLayout.CENTER);

        JPanel controls = new JPanel(new BorderLayout(8, 8));
        controls.add(export, BorderLayout.WEST);
        controls.add(status, BorderLayout.CENTER);
        add(controls, BorderLayout.SOUTH);
        export.addActionListener(event -> export());
    }

    private void export() {
        if (closed.get() || !exporting.compareAndSet(false, true)) return;
        export.setEnabled(false);
        status.setText("Exporting...");
        final ExportConfiguration configuration;
        try {
            configuration = new ExportConfiguration(
                    origin.getText(),
                    pathPrefix.getText(),
                    CaptureSanitizer.commaSeparatedLiterals(pathLiterals.getText()),
                    ((Number) maxItems.getValue()).intValue(),
                    Path.of(output.getText()));
        } catch (RuntimeException error) {
            finish("Refused: " + safeMessage(error));
            return;
        }

        try {
            worker.submit(() -> {
                try {
                    ProxyHistoryExporter.ExportSummary summary = exporter.export(configuration);
                    finish("Exported " + summary.exported() + " item(s); skipped "
                            + (summary.offScope() + summary.malformed() + summary.limitOmitted()) + ".");
                } catch (Exception error) {
                    finish("Failed: " + safeMessage(error));
                }
            });
        } catch (RejectedExecutionException error) {
            finish(closed.get() ? "Unloaded" : "Failed: export worker unavailable");
        }
    }

    private void finish(String message) {
        SwingUtilities.invokeLater(() -> {
            exporting.set(false);
            status.setText(closed.get() ? "Unloaded" : message);
            export.setEnabled(!closed.get());
        });
    }

    private static String safeMessage(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.isBlank()) return error.getClass().getSimpleName();
        return message.replaceAll("[\\p{Cntrl}\\u2028\\u2029]", " ");
    }

    private static void addRow(JPanel form, int row, String label, java.awt.Component component) {
        GridBagConstraints left = new GridBagConstraints();
        left.gridx = 0;
        left.gridy = row;
        left.anchor = GridBagConstraints.LINE_START;
        left.insets = new Insets(4, 4, 4, 12);
        form.add(new JLabel(label), left);

        GridBagConstraints right = new GridBagConstraints();
        right.gridx = 1;
        right.gridy = row;
        right.weightx = 1;
        right.fill = GridBagConstraints.HORIZONTAL;
        right.insets = new Insets(4, 4, 4, 4);
        form.add(component, right);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        worker.shutdownNow();
        SwingUtilities.invokeLater(() -> {
            export.setEnabled(false);
            status.setText("Unloaded");
        });
    }
}
