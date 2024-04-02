package io.horizen.account.state

import io.horizen.account.state.nativescdata.forgerstakev2.ForgerDetails

case class PagedForgersListResponse(nextStartPos: Int, forgers: Seq[ForgerDetails])
