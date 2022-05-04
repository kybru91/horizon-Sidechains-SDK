package com.horizen.utils

class FeeRate(fee: Long, size: Long) {
  private val satoshiPerK : Long = if (size > 0) {
    fee*1000/size
  } else {
    0
  }

  def getFee(size: Long): Long = {
    val fee = satoshiPerK / 1000
    if (fee == 0 && satoshiPerK > 0) {
      satoshiPerK
    } else {
      fee
    }
  }

  // TODO add other ops
  def >(that: FeeRate) : Boolean =
    this.satoshiPerK > that.satoshiPerK

  override def toString() = {
    s"FeeRate(${satoshiPerK / ZenCoinsUtils.COIN}.${satoshiPerK % ZenCoinsUtils.COIN} Zen/Kb)"
  }

}
