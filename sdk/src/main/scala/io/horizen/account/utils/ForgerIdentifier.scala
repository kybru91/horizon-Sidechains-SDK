package io.horizen.account.utils

import io.horizen.account.proposition.AddressProposition
import io.horizen.account.state.ForgerPublicKeys

class ForgerIdentifier(
  address: AddressProposition,
  forgerKeys: Option[ForgerPublicKeys] = None,
) {
  def getAddress: AddressProposition = address
  def getForgerKeys: Option[ForgerPublicKeys] = forgerKeys

  override def equals(obj: Any): Boolean =
    obj match {
      case that: ForgerIdentifier =>
        if (forgerKeys.isDefined) {
          address.equals(that.getAddress) && that.getForgerKeys.isDefined && forgerKeys.get.equals(that.getForgerKeys.get)
        } else {
          that.getForgerKeys.isEmpty && address.equals(that.getAddress)
        }
      case _ => false
    }

  override def hashCode(): Int = {
    if (forgerKeys.isDefined) {
      val state = Seq(address, forgerKeys.get)
      state.map(_.hashCode()).foldLeft(0)((a, b) => 31 * a + b)
    } else {
      address.hashCode()
    }
  }
}
