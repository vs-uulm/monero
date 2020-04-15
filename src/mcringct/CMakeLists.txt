set(mcringct_sources
  mcrctSigs.cpp
)

set(mcringct_headers)

set(mcringct_private_headers
  mcrctSigs.h
)

monero_private_headers(mcringct
  ${crypto_private_headers})
monero_add_library(mcringct
  ${mcringct_sources}
  ${mcringct_headers}
  ${mcringct_private_headers})
target_link_libraries(mcringct
  PUBLIC
    common
    cncrypto
    cryptonote_basic
    device
  PRIVATE
    ${OPENSSL_LIBRARIES}
    ${EXTRA_LIBRARIES})
