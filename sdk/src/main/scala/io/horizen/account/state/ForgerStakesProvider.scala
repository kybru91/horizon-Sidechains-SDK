package io.horizen.account.state

import io.horizen.evm.Address

import java.math.BigInteger

trait ForgerStakesProvider {

  private[horizen] def getPagedListOfForgersStakes(view: BaseAccountStateView, startPos: Int, pageSize: Int): (Int, Seq[AccountForgingStakeInfo])

  private[horizen] def getListOfForgersStakes(view: BaseAccountStateView, isForkV1_3Active: Boolean): Seq[AccountForgingStakeInfo]

  private[horizen] def addScCreationForgerStake(view: BaseAccountStateView, owner: Address, value: BigInteger, data: AddNewStakeCmdInput): Array[Byte]

  private[horizen] def findStakeData(view: BaseAccountStateView, stakeId: Array[Byte], isForkV1_3Active: Boolean): Option[ForgerStakeData]

  private[horizen] def isForgerListOpen(view: BaseAccountStateView): Boolean

  private[horizen] def isForgerStakeAvailable(view: BaseAccountStateView, isForkV1_3Active: Boolean): Boolean

  private[horizen] def getAllowedForgerListIndexes(view: BaseAccountStateView): Seq[Int]

  private[horizen] def isActive(view: BaseAccountStateView): Boolean
}
