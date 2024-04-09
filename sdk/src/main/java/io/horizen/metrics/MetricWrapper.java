package io.horizen.metrics;
import io.prometheus.metrics.core.metrics.Metric;
public class MetricWrapper<T extends Metric > {

    private T metric;
    private String help;



    public MetricWrapper(T metric, String help){
        this.metric = metric;
        this.help = help;
    }

    public T getMetric() {
        return metric;
    }

    public String getHelp() {
        return help;
    }
}
