
#include "MFRC522Scard.h"

// from:
// https://github.com/smartcardservices/smartcardservices/blob/56d046746be2ae4f68bdf58980df588b4d0e6a16/Tokend/Tokend/SCardError.h

/* ISO/IEC 7816 part 3 and 4 error codes. */

/** success */
#define SCARD_SUCCESS 0x9000

/* '61XX'	SW2 indicates the number of response bytes still available. */
#define SCARD_BYTES_LEFT_IN_SW2 0x6100

/* '62XX'	Warning processings - State of non-volatile memory unchanged. */

/** Execution warning, state of non-volatile memory unchanged */
#define SCARD_EXECUTION_WARNING 0x6200

/** Part of returned data may be corrupted. */
#define SCARD_RETURNED_DATA_CORRUPTED 0x6281

/** End of file/record reached before reading Le bytes. */
#define SCARD_END_OF_FILE_REACHED 0x6282

/** Selected file invalidated. */
#define SCARD_FILE_INVALIDATED 0x6283

/** FCI not formatted according to 1.1.5. */
#define SCARD_FCI_INVALID 0x6284

/* '62XX'	Warning processings - State of non-volatile memory changed. */

/** Authentication failed. */
#define SCARD_AUTHENTICATION_FAILED 0x6300

/** File filled up by the last write. */
#define SCARD_FILE_FILLED 0x6381

/** Authentication failed, 0 retries left. */
#define SCARD_AUTHENTICATION_FAILED_0 0x63C0

/** Authentication failed, 1 retry left. */
#define SCARD_AUTHENTICATION_FAILED_1 0x63C1

/** Authentication failed, 2 retries left. */
#define SCARD_AUTHENTICATION_FAILED_2 0x63C2

/** Authentication failed, 3 retries left. */
#define SCARD_AUTHENTICATION_FAILED_3 0x63C3

/** Authentication failed, 4 retries left. */
#define SCARD_AUTHENTICATION_FAILED_4 0x63C4

/** Authentication failed, 5 retries left. */
#define SCARD_AUTHENTICATION_FAILED_5 0x63C5

/** Authentication failed, 6 retries left. */
#define SCARD_AUTHENTICATION_FAILED_6 0x63C6

/** Authentication failed, 7 retries left. */
#define SCARD_AUTHENTICATION_FAILED_7 0x63C7

/** Authentication failed, 8 retries left. */
#define SCARD_AUTHENTICATION_FAILED_8 0x63C8

/** Authentication failed, 9 retries left. */
#define SCARD_AUTHENTICATION_FAILED_9 0x63C9

/** Authentication failed, 10 retries left. */
#define SCARD_AUTHENTICATION_FAILED_10 0x63CA

/** Authentication failed, 11 retries left. */
#define SCARD_AUTHENTICATION_FAILED_11 0x63CB

/** Authentication failed, 12 retries left. */
#define SCARD_AUTHENTICATION_FAILED_12 0x63CC

/** Authentication failed, 13 retries left. */
#define SCARD_AUTHENTICATION_FAILED_13 0x63CD

/** Authentication failed, 14 retries left. */
#define SCARD_AUTHENTICATION_FAILED_14 0x63CE

/** Authentication failed, 15 retries left. */
#define SCARD_AUTHENTICATION_FAILED_15 0x63CF

/* '64XX'	Execution errors - State of non-volatile memory unchanged. */

/** Execution error, state of non-volatile memory unchanged. */
#define SCARD_EXECUTION_ERROR 0x6400

/* '65XX'	Execution errors - State of non-volatile memory changed. */

/** Execution error, state of non-volatile memory changed. */
#define SCARD_CHANGED_ERROR 0x6500

/** Memory failure. */
#define SCARD_MEMORY_FAILURE 0x6581

/* '66XX'	Reserved for security-related issues. */

/* '6700'	Wrong length. */

/** The length is incorrect. */
#define SCARD_LENGTH_INCORRECT 0x6700

/* '68XX'	Functions in CLA not supported. */

/** No information given. */
#define SCARD_CLA_UNSUPPORTED 0x6800

/** Logical channel not supported. */
#define SCARD_LOGICAL_CHANNEL_UNSUPPORTED 0x6881

/** Secure messaging not supported. */
#define SCARD_SECURE_MESSAGING_UNSUPPORTED 0x6882

/* '69XX'	Command not allowed. */

/** Command not allowed. */
#define SCARD_COMMAND_NOT_ALLOWED 0x6900

/** Command incompatible with file structure. */
#define SCARD_COMMAND_INCOMPATIBLE 0x6981

/** Security status not satisfied. */
#define SCARD_NOT_AUTHORIZED 0x6982

/** Authentication method blocked. */
#define SCARD_AUTHENTICATION_BLOCKED 0x6983

/** Referenced data invalidated. */
#define SCARD_REFERENCED_DATA_INVALIDATED 0x6984

/** Conditions of use not satisfied. */
#define SCARD_USE_CONDITIONS_NOT_MET 0x6985

/** Command not allowed (no current EF). */
#define SCARD_NO_CURRENT_EF 0x6986

/** Expected SM data objects missing. */
#define SCARD_SM_DATA_OBJECTS_MISSING 0x6987

/** SM data objects incorrect. */
#define SCARD_SM_DATA_NOT_ALLOWED 0x6988

/* '6AXX'	Wrong parameter(s) P1-P2. */

/** Wrong parameter. */
#define SCARD_WRONG_PARAMETER 0x6A00

/** Incorrect parameters in the data field. */
#define SCARD_DATA_INCORRECT 0x6A80

/** Function not supported. */
#define SCARD_FUNCTION_NOT_SUPPORTED 0x6A81

/** File not found. */
#define SCARD_FILE_NOT_FOUND 0x6A82

/** Record not found. */
#define SCARD_RECORD_NOT_FOUND 0x6A83

/** Not enough memory space in the file. */
#define SCARD_NO_MEMORY_LEFT 0x6A84

/** Lc inconsistent with TLV structure. */
#define SCARD_LC_INCONSISTENT_TLV 0x6A85

/** Incorrect parameters P1-P2. */
#define SCARD_INCORRECT_P1_P2 0x6A86

/** Lc inconsistent with P1-P2. */
#define SCARD_LC_INCONSISTENT_P1_P2 0x6A87

/** Referenced data not found. */
#define SCARD_REFERENCED_DATA_NOT_FOUND 0x6A88

/* '6B00'	Wrong parameter(s) P1-P2. */

/** Wrong parameter(s) P1-P2. */
#define SCARD_WRONG_PARAMETER_P1_P2 0x6B00

/* '6CXX'	Wrong length Le: SW2 indicates the exact length */
#define SCARD_LE_IN_SW2 0x6C00

/* '6D00'	Instruction code not supported or invalid. */

/** The instruction code is not programmed or is invalid. */
#define SCARD_INSTRUCTION_CODE_INVALID 0x6D00

/* '6E00'	Class not supported. */

/** The card does not support the instruction class. */
#define SCARD_INSTRUCTION_CLASS_UNSUPPORTED 0x6E00

/* '6F00'	No precise diagnosis. */

/** No precise diagnostic is given. */
#define SCARD_UNSPECIFIED_ERROR 0x6F00

const char* MFRC522Scard::GetScardStatus(
    byte* SW1_2) {  ///< SW1, SW2 status bytes
  uint16_t SW = SW1_2[0] << 8 | SW1_2[1];
  switch (SW) {
    case SCARD_SUCCESS:
      return "Success";
    case SCARD_BYTES_LEFT_IN_SW2:
      return "SW2 indicates the number of response bytes still available";
    case SCARD_EXECUTION_WARNING:
      return "Execution warning, state of non-volatile memory unchanged";
    case SCARD_RETURNED_DATA_CORRUPTED:
      return "Part of returned data may be corrupted.";
    case SCARD_END_OF_FILE_REACHED:
      return "End of file/record reached before reading Le bytes.";
    case SCARD_FILE_INVALIDATED:
      return "Selected file invalidated.";
    case SCARD_FCI_INVALID:
      return "FCI not formatted according to 1.1.5.";
    case SCARD_AUTHENTICATION_FAILED:
      return "Authentication failed.";
    case SCARD_FILE_FILLED:
      return "File filled up by the last write.";
    case SCARD_AUTHENTICATION_FAILED_0:
      return "Authentication failed, 0 retries left.";
    case SCARD_AUTHENTICATION_FAILED_1:
      return "Authentication failed, 1 retry left.";
    case SCARD_AUTHENTICATION_FAILED_2:
      return "Authentication failed, 2 retries left.";
    case SCARD_AUTHENTICATION_FAILED_3:
      return "Authentication failed, 3 retries left.";
    case SCARD_AUTHENTICATION_FAILED_4:
      return "Authentication failed, 4 retries left.";
    case SCARD_AUTHENTICATION_FAILED_5:
      return "Authentication failed, 5 retries left.";
    case SCARD_AUTHENTICATION_FAILED_6:
      return "Authentication failed, 6 retries left.";
    case SCARD_AUTHENTICATION_FAILED_7:
      return "Authentication failed, 7 retries left.";
    case SCARD_AUTHENTICATION_FAILED_8:
      return "Authentication failed, 8 retries left.";
    case SCARD_AUTHENTICATION_FAILED_9:
      return "Authentication failed, 9 retries left.";
    case SCARD_AUTHENTICATION_FAILED_10:
      return "Authentication failed, 10 retries left.";
    case SCARD_AUTHENTICATION_FAILED_11:
      return "Authentication failed, 11 retries left.";
    case SCARD_AUTHENTICATION_FAILED_12:
      return "Authentication failed, 12 retries left.";
    case SCARD_AUTHENTICATION_FAILED_13:
      return "Authentication failed, 13 retries left.";
    case SCARD_AUTHENTICATION_FAILED_14:
      return "Authentication failed, 14 retries left.";
    case SCARD_AUTHENTICATION_FAILED_15:
      return "Authentication failed, 15 retries left.";
    case SCARD_EXECUTION_ERROR:
      return "Execution error, state of non-volatile memory unchanged.";
    case SCARD_CHANGED_ERROR:
      return "Execution error, state of non-volatile memory changed.";
    case SCARD_MEMORY_FAILURE:
      return "Memory failure.";
    case SCARD_LENGTH_INCORRECT:
      return "The length is incorrect.";
    case SCARD_CLA_UNSUPPORTED:
      return "Functions in CLA not supported.";
    case SCARD_LOGICAL_CHANNEL_UNSUPPORTED:
      return "Logical channel not supported.";
    case SCARD_SECURE_MESSAGING_UNSUPPORTED:
      return "Secure messaging not supported.";
    case SCARD_COMMAND_NOT_ALLOWED:
      return "Command not allowed.";
    case SCARD_COMMAND_INCOMPATIBLE:
      return "Command incompatible with file structure.";
    case SCARD_NOT_AUTHORIZED:
      return "Security status not satisfied.";
    case SCARD_AUTHENTICATION_BLOCKED:
      return "Authentication method blocked.";
    case SCARD_REFERENCED_DATA_INVALIDATED:
      return "Referenced data invalidated.";
    case SCARD_USE_CONDITIONS_NOT_MET:
      return "Conditions of use not satisfied.";
    case SCARD_NO_CURRENT_EF:
      return "Command not allowed (no current EF).";
    case SCARD_SM_DATA_OBJECTS_MISSING:
      return "Expected SM data objects missing.";
    case SCARD_SM_DATA_NOT_ALLOWED:
      return "SM data objects incorrect.";
    case SCARD_WRONG_PARAMETER:
      return "Wrong parameter.";
    case SCARD_DATA_INCORRECT:
      return "Incorrect parameters in the data field.";
    case SCARD_FUNCTION_NOT_SUPPORTED:
      return "Function not supported.";
    case SCARD_FILE_NOT_FOUND:
      return "File not found.";
    case SCARD_RECORD_NOT_FOUND:
      return "Record not found.";
    case SCARD_NO_MEMORY_LEFT:
      return "Not enough memory space in the file.";
    case SCARD_LC_INCONSISTENT_TLV:
      return "Lc inconsistent with TLV structure.";
    case SCARD_INCORRECT_P1_P2:
      return "Incorrect parameters P1-P2.";
    case SCARD_LC_INCONSISTENT_P1_P2:
      return "Lc inconsistent with P1-P2.";
    case SCARD_REFERENCED_DATA_NOT_FOUND:
      return "Referenced data not found.";
    case SCARD_WRONG_PARAMETER_P1_P2:
      return "Wrong parameter(s) P1-P2.";
    case SCARD_LE_IN_SW2:
      return "Wrong length Le: SW2 indicates the exact length";
    case SCARD_INSTRUCTION_CODE_INVALID:
      return "The instruction code is not programmed or is invalid.";
    case SCARD_INSTRUCTION_CLASS_UNSUPPORTED:
      return "The card does not support the instruction class.";
    case SCARD_UNSPECIFIED_ERROR:
      return "No precise diagnostic is given.";
    default:
      return "Unknown error";
  }
}
