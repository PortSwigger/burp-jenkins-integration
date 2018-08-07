package org.jenkinsci.plugins.burpscan;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Builder;
import net.portswigger.burp.api.driver.BurpCiDriver;
import net.portswigger.burp.api.driver.BurpCiSourceConsumer;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;

public class BurpScanRecorder extends Builder
{
    @Extension
    public static final BuildStepDescriptor<Builder> DESCRIPTOR = new BuildStepDescriptor<Builder>()
    {
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType)
        {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Burp scan";
        }
    };

    private final String apiUrl;
    private final String scanDefinitionJson;
    private final String severityThreshold;
    private final String confidenceThreshold;
    private boolean outputJsonIssues;

    @DataBoundConstructor
    public BurpScanRecorder(
            String apiUrl,
            String scanDefinitionJson,
            String severityThreshold,
            String confidenceThreshold,
            boolean outputJsonIssues
    ) {
        this.apiUrl = apiUrl;
        this.scanDefinitionJson = scanDefinitionJson;
        this.severityThreshold = severityThreshold;
        this.confidenceThreshold = confidenceThreshold;
        this.outputJsonIssues = outputJsonIssues;
    }

    // getters for data-binding

    @SuppressWarnings("unused")
    public String getApiUrl()
    {
        return apiUrl;
    }

    @SuppressWarnings("unused")
    public String getScanDefinitionJson()
    {
        return scanDefinitionJson;
    }

    @SuppressWarnings("unused")
    public String getSeverityThreshold()
    {
        return severityThreshold;
    }

    @SuppressWarnings("unused")
    public String getConfidenceThreshold()
    {
        return confidenceThreshold;
    }

    @SuppressWarnings("unused")
    public boolean getOutputJsonIssues()
    {
        return outputJsonIssues;
    }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener)
    {
//        listener.getLogger().println("DEBUG: apiUrl = " + apiUrl);
//        listener.getLogger().println("DEBUG: scanDefinitionJson = " + scanDefinitionJson);
//        listener.getLogger().println("DEBUG: severityThreshold = " + severityThreshold);
//        listener.getLogger().println("DEBUG: confidenceThreshold = " + confidenceThreshold);
//        listener.getLogger().println("DEBUG: outputJsonIssues = " + outputJsonIssues);

        BurpCiSourceConsumer burpCiSourceConsumer = BurpCiSourceConsumer.fromReader(logReader(build));

        try {
            return new BurpCiDriver(
                        apiUrl,
                    scanDefinitionJson,
                        burpCiSourceConsumer.getUrls(),
                        severityThreshold,
                        confidenceThreshold,
                        burpCiSourceConsumer.getIgnores(),
                        null,
                        null,
                        outputJsonIssues ? listener.getLogger()::println : null)
                    .scan(listener.getLogger()::println)
                    .isEmpty();
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
        catch (InterruptedException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static BufferedReader logReader(AbstractBuild<?, ?> build)
    {
        try
        {
            return new BufferedReader(new FileReader(build.getLogFile()));
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public BuildStepMonitor getRequiredMonitorService()
    {
        return BuildStepMonitor.NONE;
    }

    @Override
    public BuildStepDescriptor getDescriptor()
    {
        return DESCRIPTOR;
    }
}
