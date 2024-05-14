package io.horizen.account.utils

import io.horizen.account.proposition.AddressProposition
import io.horizen.proposition.{PublicKey25519Proposition, VrfPublicKey}

case class ForgerIdentifier(
  address: AddressProposition,
  blockSignPublicKey: Option[PublicKey25519Proposition] = None,
  vrfPublicKey: Option[VrfPublicKey] = None,
)
