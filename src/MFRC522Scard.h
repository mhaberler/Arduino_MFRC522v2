/* SPDX-License-Identifier: LGPL-2.1 */
#pragma once

#include <Arduino.h>
#include <MFRC522Constants.h>
#include <MFRC522v2.h>

class MFRC522Scard {

public:
  static const char *GetScardStatus(byte* SW1_2);

};
