package io.horizen.account.state

import io.horizen.consensus.ForgingStakeInfo

trait ForgerStakesProviderV2 {

  private[horizen] def getPagedListOfForgersStakes(view: BaseAccountStateView, startPos: Int, pageSize: Int): PagedForgersListResponse

  private[horizen] def getListOfForgersStakes(view: BaseAccountStateView): Seq[AccountForgingStakeInfo]

  private[horizen] def getForgingStakes(view: BaseAccountStateView): Seq[ForgingStakeInfo]

  private[horizen] def isActive(view: BaseAccountStateView): Boolean
}
