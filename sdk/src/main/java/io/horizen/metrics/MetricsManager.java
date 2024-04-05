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
    private Counter blocksAppliedSuccesfully;
    private Counter blocksNotApplied;
    private Gauge blockApplyTime;
    private Gauge blockApplyTimeAbsolute;
    private Gauge mempoolSize;

    private Gauge forgeLotteryTime;

    private Gauge forgeBlockCreationTime;

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

        //Time to apply blocks (milliseconds)
        blockApplyTime  = Gauge.builder()
                .name("block_apply_time")
                .register();

        //Delta between block timestamp and timestamp when block has been applied succesfully (milliseconds)
        blockApplyTimeAbsolute = Gauge.builder()
                .name("block_apply_time_absolute")
                .register();

        //Number of received blocks applied succesfully (absolute value since start of the node)
        blocksAppliedSuccesfully = Counter.builder()
                .name("block_applied_ok")
                .register();

        //Number of received blocks not applied (absolute value since start of the node)
        blocksNotApplied = Counter.builder()
                .name("block_applied_ko")
                .register();

        //Mempool size (number of transactions)
        mempoolSize = Gauge.builder()
                .name("mempool_size")
                .register();

        //Time to execute lottery (milliseconds)
        forgeLotteryTime  = Gauge.builder()
                .name("forge_lottery_time")
                .register();

        //Time to create a new forged block
        forgeBlockCreationTime  = Gauge.builder()
                .name("forge_blockcreation_time")
                .register();

    }

    public void appliedBlockOk(long time, long timeFromBlockStamp){
        blockApplyTime.set(time);
        blockApplyTimeAbsolute.set(timeFromBlockStamp);
        blocksAppliedSuccesfully.inc();
    }

    public void forgedBlock(long time){
        forgeBlockCreationTime.set(time);
    }
    public void appliedBlockKo(){
        blocksNotApplied.inc();
    }
    public void mempoolSize(int size){
        mempoolSize.set(size);
    }

    public void lotteryDone(long duration){
        forgeLotteryTime.set(duration);
    }




}
