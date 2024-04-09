package io.horizen.metrics;

import io.horizen.block.SidechainBlockBase;
import io.horizen.block.SidechainBlockBase$;
import io.prometheus.metrics.core.metrics.Counter;
import io.prometheus.metrics.core.metrics.Gauge;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sparkz.core.utils.NetworkTimeProvider;

import java.io.IOException;


public class MetricsManager {

    protected static final Logger logger = LogManager.getLogger();
    private static MetricsManager me;
    private MetricWrapper<Counter> blocksAppliedSuccesfully;
    private MetricWrapper<Counter> blocksNotApplied;
    private MetricWrapper<Gauge> blockApplyTime;
    private MetricWrapper<Gauge> blockApplyTimeAbsolute;
    private MetricWrapper<Gauge> mempoolSize;
    private MetricWrapper<Gauge> forgeLotteryTime;
    private MetricWrapper<Gauge> forgeBlockCreationTime;

    public static MetricsManager getInstance(){
        if (me == null){
            throw new RuntimeException("Metrics manager not initialized!");
        }
        return me;
    }

    public static void init() throws IOException {
        me = new MetricsManager();
    }

    private MetricsManager() throws IOException {
        logger.debug("Initializing metrics engine");

        //JvmMetrics.builder().register(); // initialize the out-of-the-box JVM metrics

        blockApplyTime  =  new MetricWrapper<Gauge>(
                Gauge.builder().name("block_apply_time").register(),
                "Time to apply block (milliseconds)"
        );

        blockApplyTimeAbsolute = new MetricWrapper<Gauge>(
                Gauge.builder().name("block_apply_time_absolute").register(),
                "Delta between block timestamp and timestamp when block has been applied succesfully on this node (milliseconds)"
        );

        blocksAppliedSuccesfully = new MetricWrapper<Counter>(
                Counter.builder().name("block_applied_ok").register(),
                "Number of received blocks applied succesfully (absolute value since start of the node)"
        );

        blocksNotApplied = new MetricWrapper<Counter>(
                Counter.builder().name("block_applied_ko").register(),
                "Number of received blocks not applied (absolute value since start of the node)"
        );

        mempoolSize = new MetricWrapper<Gauge>(
                Gauge.builder().name("mempool_size").register(),
                "Mempool size (number of transactions in this node mempool)"
        );

        forgeLotteryTime = new MetricWrapper<Gauge>(
                Gauge.builder().name("forge_lottery_time").register(),
                "Time to execute the lottery (milliseconds)"
        );

        forgeBlockCreationTime = new MetricWrapper<Gauge>(
                Gauge.builder().name("forge_blockcreation_time").register(),
                "Time to create a new forged block (milliseconds)"
        );
    }

    public void appliedBlockOk(long millis, long millisFromBlockStamp){
        blockApplyTime.getMetric().set(millis);
        blockApplyTimeAbsolute.getMetric().set(millisFromBlockStamp);
        blocksAppliedSuccesfully.getMetric().inc();
    }

    public void forgedBlock(long millis){
        forgeBlockCreationTime.getMetric().set(millis);
    }
    public void appliedBlockKo(){
        blocksNotApplied.getMetric().inc();
    }
    public void mempoolSize(int size){
        mempoolSize.getMetric().set(size);
    }
    public void lotteryDone(long millis){
        forgeLotteryTime.getMetric().set(millis);
    }


}
