package io.horizen.metrics;

import io.prometheus.metrics.core.metrics.Counter;
import io.prometheus.metrics.core.metrics.Gauge;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sparkz.core.utils.TimeProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


public class MetricsManager {

    protected static final Logger logger = LogManager.getLogger();

    private TimeProvider timeProvider;
    private static MetricsManager me;
    private Counter blocksAppliedSuccesfully;
    private Counter blocksNotApplied;
    private Gauge blockApplyTime;
    private Gauge blockApplyTimeAbsolute;
    private Gauge mempoolSize;
    private Gauge forgeLotteryTime;
    private Gauge forgeBlockCreationTime;

    private List<MetricsHelp> helps;

    public static MetricsManager getInstance(){
        if (me == null){
            throw new RuntimeException("Metrics manager not initialized!");
        }
        return me;
    }

    public static void init(TimeProvider timeProvider) throws IOException {
        if (me == null){
            me = new MetricsManager(timeProvider);
        }
    }

    private MetricsManager(TimeProvider timeProvider) throws IOException {
        logger.debug("Initializing metrics engine");

        this.timeProvider = timeProvider;

        //JvmMetrics.builder().register(); // initialize the out-of-the-box JVM metrics
        helps = new ArrayList<>();

        blockApplyTime  =  Gauge.builder().name("block_apply_time").register();
        helps.add(new MetricsHelp(blockApplyTime.getPrometheusName(), "Time to apply block to node wallet and state (milliseconds)"));

        blockApplyTimeAbsolute =  Gauge.builder().name("block_apply_time_fromforging").register();
        helps.add(new MetricsHelp(blockApplyTimeAbsolute.getPrometheusName(), "Delta between timestamp when block has been applied succesfully on this node and timestamp of the block indicated by the forger (milliseconds)"));

        blocksAppliedSuccesfully =   Counter.builder().name("block_applied_ok").register();
        helps.add(new MetricsHelp(blocksAppliedSuccesfully.getPrometheusName(),"Number of received blocks applied succesfully (absolute value since start of the node)"));

        blocksNotApplied =  Counter.builder().name("block_applied_ko").register();
        helps.add(new MetricsHelp(blocksNotApplied.getPrometheusName(), "Number of received blocks not applied (absolute value since start of the node)"));

        mempoolSize =  Gauge.builder().name("mempool_size").register();
        helps.add(new MetricsHelp(mempoolSize.getPrometheusName(), "Mempool size (number of transactions in this node mempool)"));

        forgeLotteryTime = Gauge.builder().name("forge_lottery_time").register();
        helps.add(new MetricsHelp(forgeLotteryTime.getPrometheusName(), "Time to execute the lottery (milliseconds)"));

        forgeBlockCreationTime = Gauge.builder().name("forge_blockcreation_time").register();
        helps.add(new MetricsHelp(forgeBlockCreationTime.getPrometheusName(),  "Time to create a new forged block (milliseconds)"));
    }

    public long currentMillis(){
        return timeProvider.time();
    }

    public List<MetricsHelp> getHelp(){
        return helps;
    }

    public void appliedBlockOk(long millis, long millisFromBlockStamp){
        blockApplyTime.set(millis);
        blockApplyTimeAbsolute.set(millisFromBlockStamp);
        blocksAppliedSuccesfully.inc();
    }

    public void forgedBlock(long millis){
        forgeBlockCreationTime.set(millis);
    }
    public void appliedBlockKo(){
        blocksNotApplied.inc();
    }
    public void mempoolSize(int size){
        mempoolSize.set(size);
    }
    public void lotteryDone(long millis){
        forgeLotteryTime.set(millis);
    }


}
