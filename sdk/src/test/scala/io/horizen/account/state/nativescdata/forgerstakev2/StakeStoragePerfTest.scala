package io.horizen.account.state.nativescdata.forgerstakev2

import io.horizen.account.state._
import io.horizen.account.state.nativescdata.forgerstakev2.StakeStorage._
import io.horizen.account.utils.WellKnownAddresses.FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS
import io.horizen.account.utils.ZenWeiConverter
import io.horizen.consensus.{ForgingStakeInfo, minForgerStake}
import io.horizen.evm.{Address, Hash, MemoryDatabase, StateDB}
import io.horizen.fixtures.StoreFixture
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}
import io.horizen.utils.{ByteArrayWrapper, BytesUtils, ForgingStakeMerklePathInfo, MerkleTree}
import org.junit.{Ignore, Test}
import org.scalatestplus.junit.JUnitSuite

import java.io.{BufferedWriter, FileWriter}
import java.math.BigInteger
import java.util.Calendar
import scala.collection.JavaConverters._
import scala.language.implicitConversions

class StakeStoragePerfTest
  extends JUnitSuite
    with MessageProcessorFixture
    with StoreFixture {

  val blockSignerProposition1 = new PublicKey25519Proposition(BytesUtils.fromHexString("1122334455667788112233445566778811223344556677881122334455667788")) // 32 bytes
  val vrfPublicKey1 = new VrfPublicKey(BytesUtils.fromHexString("d6b775fd4cefc7446236683fdde9d0464bba43cc565fa066b0b3ed1b888b9d1180")) // 33 bytes
  val forger1Key: ForgerKey = ForgerKey(blockSignerProposition1, vrfPublicKey1)

  val delegator1 = new Address("0xaaa00001230000000000deadbeefaaaa2222de01")


  @Ignore
  @Test
  def testMultipleForgers(): Unit = {

    val cal = Calendar.getInstance()
    using(new MemoryDatabase()) { db =>

      var stateDb = new StateDB(db, Hash.ZERO)
      //  Setup account
      using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
        createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
        val rootHash = stateDb.commit()
        stateDb = new StateDB(db, rootHash)
      }

      val epochNumber = 135869
      val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
      val rewardShare = 93

      val numOfSnapshots = 100

      val numOfForgers = 1000
      val numOfForgersPerSnapshot = numOfForgers / numOfSnapshots

      val listOfForgerKeysWithDelegator = (1 to numOfForgers).map(
        idx_forg => {
          val postfix32 = f"$idx_forg%064X"
          val blockSignerProposition = new PublicKey25519Proposition(BytesUtils.fromHexString(s"$postfix32")) // 32 bytes
          val vrfPublicKey = new VrfPublicKey(BytesUtils.fromHexString(s"d2$postfix32")) // 33 bytes
          val postfix20 = f"$idx_forg%040X"
          val delegator = new Address(s"0x$postfix20")
          (blockSignerProposition, vrfPublicKey, delegator)
        })


      using(new BufferedWriter(new FileWriter(s"log/testAddForgers_${cal.getTimeInMillis}.csv", true))) { out =>
        // This tests if addForger method increases its time of execution increasing the number of forgers.
        // It tests also:
        // - the time of the operations performed by the lottery, i.e. getForgingStakes (including filtering),
        //   creation of the Merkle tree and creation of the Merkle Path.
        // - The time and the gas consumed by stakeTotal method.

        out.write("#*********************************************************************\n\n")
        out.write("#*                Adding forger performance test                      \n\n")
        out.write("#*********************************************************************\n\n")

        out.write(s"# Date and time of the test: ${cal.getTime}\n\n")

        out.write(s"#Total number of forgers:                        $numOfForgers\n")
        out.write(s"#Number of snapshots:                            $numOfSnapshots\n")
        out.write(s"#Number of forgers for each snapshot:            $numOfForgersPerSnapshot\n")

        println(s"*************** Adding forgers performance test ***************")
        println(s"Total number of forgers: $numOfForgers")

        val listOfSnapshotResults = new scala.collection.mutable.ListBuffer[(Float, Long, Long, Long, Long, BigInteger)]()

        listOfForgerKeysWithDelegator.grouped(numOfForgersPerSnapshot).foreach { listOfForgersPerSnapshot =>
          var startTime = System.currentTimeMillis()
          listOfForgersPerSnapshot.foreach { case (pubSignKey, vrfKey, delegator) =>
            using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
              StakeStorage.addForger(view, pubSignKey, vrfKey, rewardShare, rewardAddress, epochNumber, delegator, ZenWeiConverter.convertZenniesToWei(minForgerStake))
              val rootHash = stateDb.commit()
              stateDb = new StateDB(db, rootHash)
            }
          }
          val addForgerTime = System.currentTimeMillis() - startTime
          using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
            val signKeyRef = listOfForgersPerSnapshot(numOfForgersPerSnapshot / 2)._1
            val vrfKeyRef = listOfForgersPerSnapshot(numOfForgersPerSnapshot / 2)._2
            startTime = System.currentTimeMillis()
            val forgingStakeInfoSeq = StakeStorage.getForgingStakes(view).filter(fsi => fsi.stakeAmount >= minForgerStake)
              // sort the resulting sequence by decreasing stake amount
              .sorted(Ordering[ForgingStakeInfo].reverse)

            val filteredForgingStakeInfoSeq = forgingStakeInfoSeq.filter(p => {
              signKeyRef == (p.blockSignPublicKey) &&
                vrfKeyRef == p.vrfPublicKey
            })
            val filterTime = System.currentTimeMillis() - startTime

            startTime = System.currentTimeMillis()
            val forgingStakeInfoTree = MerkleTree.createMerkleTree(forgingStakeInfoSeq.map(info => info.hash).asJava)
            val merkleTreeTime = System.currentTimeMillis() - startTime

            startTime = System.currentTimeMillis()
            val merkleTreeLeaves = forgingStakeInfoTree.leaves().asScala.map(leaf => new ByteArrayWrapper(leaf))

            val forgingStakeMerklePathInfoSeq: Seq[ForgingStakeMerklePathInfo] =
              filteredForgingStakeInfoSeq.flatMap(forgingStakeInfo => {
                merkleTreeLeaves.indexOf(new ByteArrayWrapper(forgingStakeInfo.hash)) match {
                  case -1 =>
                    None
                  case index =>
                    Some(ForgingStakeMerklePathInfo(forgingStakeInfo, forgingStakeInfoTree.getMerklePathForLeaf(index)))
                }
              })
            val merklePathTime = System.currentTimeMillis() - startTime

            val gas = new GasPool(1000000000)
            val gasView = view.getGasTrackedView(gas)
            val gasBefore = gas.getGas
            startTime = System.currentTimeMillis()
            StakeStorage.getStakeTotal(gasView, None, None, epochNumber, epochNumber)
            val stakeTotalTime = System.currentTimeMillis() - startTime
            val gasUsed = gasBefore.subtract(gas.getGas)
            listOfSnapshotResults += Tuple6(addForgerTime.toFloat / numOfForgersPerSnapshot, filterTime, merkleTreeTime, merklePathTime, stakeTotalTime, gasUsed)
            val rootHash = stateDb.commit()
            stateDb = new StateDB(db, rootHash)
          }

        }

        out.write(s"\n#********************* Test results *********************\n")

        val totalTime = listOfSnapshotResults.map(_._1).sum

        println(s"AddForger total time $totalTime ms")
        val timePerForger: Float = totalTime / numOfSnapshots
        println(s"Average time per forger $timePerForger ms")
        println(
          s"Average time per forger in Snapshots ${listOfSnapshotResults.map(_._1).mkString(", ")} "
        )
        out.write(s"# AddForger total time:                      $totalTime ms\n")
        out.write(s"# Average time per forger:                   $timePerForger ms\n\n")

        out.write(s"AVG addForger Time (ms), Forger Stakes Filter Time (ms), Merkle Tree Time (ms), Merkle Path Time (ms), stakeTotal Time (ms), stakeTotal Gas\n")
        listOfSnapshotResults.foreach { res =>
          out.write(s"${res.productIterator.mkString(",")}\n")
        }

      }// FileWriter

      // Testing stakeTotal and the lottery with multiple checkpoints/epochs
      using(new BufferedWriter(new FileWriter(s"log/testMultipleEpochs_${cal.getTimeInMillis}.csv", true))) { out =>

        // This tests how stakeTotal and Lottery methods increase their time/gas increasing the number of checkpoints.
        // Checkpoints are added adding stakes to each forger in each epoch.
        // stakeTotal is measured in 3 different epochs ranges: the first epochs, the last epochs and in the middle.


      out.write("#*********************************************************************\n\n")
        out.write("#*                Adding checkpoints performance test                      \n\n")
        out.write("#*********************************************************************\n\n")
        out.write(s"# Date and time of the test: ${cal.getTime}\n\n")

        val numOfCheckpoints = 200
        val numOfCheckpointsPerSnapshot = numOfCheckpoints / numOfSnapshots
        val numOfEpochs = numOfCheckpointsPerSnapshot
        out.write(s"# Total number of checkpoints:                        $numOfCheckpoints\n")
        out.write(s"# Number of snapshots:                                $numOfSnapshots\n")
        out.write(s"# Number of checkpoints for each snapshot:            $numOfCheckpointsPerSnapshot\n")
        out.write(s"# Number of epochs for each stakeTotal call:          $numOfEpochs\n")

        println(s"*************** Adding checkpoints performance test ***************")
        println(s"Total number of checkpoints: $numOfCheckpoints")

        // In this case, we add a new delegator in any new epoch, so there is one checkpoint for delegator

        val listOfSnapshotResults = new scala.collection.mutable.ListBuffer[(Long, Long, BigInteger, Long, BigInteger, Long, BigInteger)]()

        (1 to numOfCheckpoints).foreach {  idx =>

          listOfForgerKeysWithDelegator.foreach { case (pubSignKey, vrfKey, _) =>

            using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
               StakeStorage.addStake(view, pubSignKey, vrfKey, epochNumber + idx, delegator1, ZenWeiConverter.convertZenniesToWei(minForgerStake + idx))

              val rootHash = stateDb.commit()
              stateDb = new StateDB(db, rootHash)
            }
          }
          if ((idx + 1) % numOfCheckpointsPerSnapshot == 0) {
            using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
              var startTime = System.currentTimeMillis()
              val forgingStakeInfoSeq = StakeStorage.getForgingStakes(view).filter(fsi => fsi.stakeAmount >= minForgerStake)
                // sort the resulting sequence by decreasing stake amount
                .sorted(Ordering[ForgingStakeInfo].reverse)

              val getForgingStakesTime = System.currentTimeMillis() - startTime

              val gas = new GasPool(1000000000)
              val gasView = view.getGasTrackedView(gas)
              var gasBefore = gas.getGas
              var epochStart = epochNumber
              var epochEnd = math.min(epochStart + numOfEpochs - 1, epochNumber + idx)
              startTime = System.currentTimeMillis()
              StakeStorage.getStakeTotal(gasView, None, None, epochStart, epochEnd)
              val stakeTotalTimeFirst = System.currentTimeMillis() - startTime
              val gasUsedFirst = gasBefore.subtract(gas.getGas)

              gasBefore = gas.getGas
              epochEnd = epochNumber + idx
              epochStart = math.max(epochNumber, epochEnd - numOfEpochs + 1)
              startTime = System.currentTimeMillis()
              StakeStorage.getStakeTotal(gasView, None, None, epochStart, epochEnd)
              val stakeTotalTimeLast = System.currentTimeMillis() - startTime
              val gasUsedLast = gasBefore.subtract(gas.getGas)

              gasBefore = gas.getGas
              val middleEpoch = epochNumber + idx / 2
              val a = numOfEpochs/2
              epochStart = math.max(epochNumber, middleEpoch - a + 1)
              epochEnd = math.min(epochStart + numOfEpochs - 1, epochNumber + idx)
              startTime = System.currentTimeMillis()
              StakeStorage.getStakeTotal(gasView, None, None, epochStart, epochEnd)
              val stakeTotalTimeMiddle = System.currentTimeMillis() - startTime
              val gasUsedMiddle = gasBefore.subtract(gas.getGas)
              listOfSnapshotResults += Tuple7(getForgingStakesTime, stakeTotalTimeFirst, gasUsedFirst, stakeTotalTimeLast, gasUsedLast, stakeTotalTimeMiddle, gasUsedMiddle)
              val rootHash = stateDb.commit()
              stateDb = new StateDB(db, rootHash)

            }
          }

        }

        out.write(s"getForgingStakes Time (ms), stakeTotal First Time (ms), stakeTotal First Gas, stakeTotal Last Time (ms), stakeTotal Last Gas, stakeTotal Middle Time (ms), stakeTotal Middle Gas\n")

        listOfSnapshotResults.foreach { res =>
          out.write(s"${res.productIterator.mkString(",")}\n")
        }
      }

    }

  }



  @Ignore
  @Test
  def testSingleForgerMultipleCheckpoints(): Unit = {

    val cal = Calendar.getInstance()
    using(new BufferedWriter(new FileWriter(s"log/testSingleForgerMultipleCheckpoints_${cal.getTimeInMillis}.csv", true))) { out =>

      // This tests how stakeTotal and addStake methods increase their time/gas increasing the number of checkpoints.
      // Checkpoints are added always to the same forger in each epoch.
      // stakeTotal is measured in 3 different epochs ranges: the first epochs, the last epochs and in the middle.

    out.write("#*********************************************************************\n\n")
      out.write("#*                Adding checkpoints performance test                      \n\n")
      out.write("#*********************************************************************\n\n")

      out.write(s"# Date and time of the test: ${cal.getTime}\n\n")

      val numOfCheckpoints = 10000
      val numOfSnapshots = 100
      val numOfCheckpointsPerSnapshot = numOfCheckpoints / numOfSnapshots
      val numOfEpochs = numOfCheckpointsPerSnapshot
      out.write(s"# Total number of checkpoints:                        $numOfCheckpoints\n")
      out.write(s"# Number of snapshots:                            $numOfSnapshots\n")
      out.write(s"# Number of checkpoints for each snapshot:            $numOfCheckpointsPerSnapshot\n")
      out.write(s"# Number of epochs for each stakeTotal call:          $numOfEpochs\n")

      using(new MemoryDatabase()) { db =>

        val epochNumber = 135869
        var stateDb = new StateDB(db, Hash.ZERO)
        // setup account and forger
        using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
          createSenderAccount(view, BigInteger.TEN, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
          // Create a forger
          val rewardAddress = new Address("0xaaa0000123000000000011112222aaaa22222222")
          val rewardShare = 93
          StakeStorage.addForger(view, blockSignerProposition1, vrfPublicKey1, rewardShare, rewardAddress, epochNumber, delegator1, ZenWeiConverter.convertZenniesToWei(minForgerStake))
          val rootHash = stateDb.commit()
          stateDb = new StateDB(db, rootHash)
        }

        println(s"*************** Adding checkpoints performance test ***************")
        println(s"Total number of checkpoints: $numOfCheckpoints")

        // In this case, we add a new delegator in any new epoch, so there is one checkpoint for delegator
        val listOfDelegatorsWithIndex = (1 to numOfCheckpoints).map(
          idx_forg => {
            val postfix20 = f"$idx_forg%040X"
            new Address(s"0x$postfix20")
          }).zipWithIndex

        val listOfSnapshotResults = new scala.collection.mutable.ListBuffer[(Float, Long, BigInteger, Long, BigInteger, Long, BigInteger)]()

        val forgerPubKeys = Some(ForgerPublicKeys(blockSignerProposition1, vrfPublicKey1))

        listOfDelegatorsWithIndex.grouped(numOfCheckpointsPerSnapshot).foreach { listOfDelegatorsWithIndexPerSnapshot =>
          var startTime = System.currentTimeMillis()

          listOfDelegatorsWithIndexPerSnapshot.foreach { case (delegator, idx) =>
            using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
              StakeStorage.addStake(view, blockSignerProposition1, vrfPublicKey1, epochNumber + idx, delegator, ZenWeiConverter.convertZenniesToWei(minForgerStake + idx))
              val rootHash = stateDb.commit()
              stateDb = new StateDB(db, rootHash)
            }
          }
          val addStakeTime = System.currentTimeMillis() - startTime

          using(new AccountStateView(metadataStorageView, stateDb, Seq.empty)) { view =>
            val gas = new GasPool(1000000000)
            val gasView = view.getGasTrackedView(gas)
            var gasBefore = gas.getGas
            val lastEpoch = epochNumber + listOfDelegatorsWithIndexPerSnapshot.last._2

            var epochStart = epochNumber
            var epochEnd = math.min(epochStart + numOfEpochs - 1, lastEpoch)
            startTime = System.currentTimeMillis()
            StakeStorage.getStakeTotal(gasView, forgerPubKeys, None, epochStart, epochEnd)
            val stakeTotalTimeFirst = System.currentTimeMillis() - startTime
            val gasUsedFirst = gasBefore.subtract(gas.getGas)

            gasBefore = gas.getGas
            epochEnd = lastEpoch
            epochStart = math.max(epochNumber, epochEnd - numOfEpochs + 1)
            startTime = System.currentTimeMillis()
            StakeStorage.getStakeTotal(gasView, forgerPubKeys, None, epochStart, epochEnd)
            val stakeTotalTimeLast = System.currentTimeMillis() - startTime
            val gasUsedLast = gasBefore.subtract(gas.getGas)

            gasBefore = gas.getGas
            val middleEpoch = epochNumber + listOfDelegatorsWithIndexPerSnapshot.last._2 / 2
            val a = numOfEpochs / 2
            epochStart = math.max(epochNumber, middleEpoch - a + 1)
            epochEnd = math.min(epochStart + numOfEpochs - 1, lastEpoch)
            startTime = System.currentTimeMillis()
            StakeStorage.getStakeTotal(gasView, forgerPubKeys, None, epochStart, epochEnd)
            val stakeTotalTimeMiddle = System.currentTimeMillis() - startTime
            val gasUsedMiddle = gasBefore.subtract(gas.getGas)
            listOfSnapshotResults += Tuple7(addStakeTime.toFloat / numOfCheckpointsPerSnapshot, stakeTotalTimeFirst, gasUsedFirst, stakeTotalTimeLast, gasUsedLast, stakeTotalTimeMiddle, gasUsedMiddle)
            val rootHash = stateDb.commit()
            stateDb = new StateDB(db, rootHash)
          }
        }


        out.write(s"\n# ********************* Test results *********************\n")

        val timePerStake: Float = listOfSnapshotResults.map(_._1).sum / numOfSnapshots
        println(s"Average time per stake $timePerStake ms")
        println(
          s"Average time per stake in Snapshots ${listOfSnapshotResults.map(res => res._1).mkString(", ")} "
        )
        out.write(s"# Average time per stake:             $timePerStake ms\n")
        out.write(s"addStake Time (ms), stakeTotal First Time (ms), stakeTotal First Gas, stakeTotal Last Time (ms), stakeTotal Last Gas, stakeTotal Middle Time (ms), stakeTotal Middle Gas\n")

        listOfSnapshotResults.foreach { res =>
          out.write(s"${res.productIterator.mkString(",")}\n")
        }

      }

    }


  }



}
