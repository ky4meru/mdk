/**
 * @file Log.h
 * @author Ky4meru (@ky4meru)
 * @brief Logging macros and BOF-compatible variants.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_LOG_H_
#define _MDK_LOG_H_

#include <windows.h>

#include "Macros.h"

MDK_TEXT_SEC(MDK) static VOID MdkPrintf(_In_ LPCSTR format, ...);

#ifdef _MDK_BOF
MDK_TEXT_SEC(MDK) static VOID MdkBeaconPrintf(_In_ CHAR tag, _In_ LPCSTR format, ...);
#endif // _MDK_BOF

#ifdef _MDK_DEBUG

#ifdef _MDK_BOF

/// @private
#define MDK_LOG_DEBUG( f, ... ) MdkBeaconPrintf( '?', "%s:%d | " f, __FUNCTION__, __LINE__, __VA_ARGS__ );

#else

/// @private
#define MDK_LOG_DEBUG( f, ... ) do { MdkPrintf( "\033[1;35m[?]\033[1;0m %s:%d | ", __FUNCTION__, __LINE__ ); MdkPrintf( f, __VA_ARGS__ ); MdkPrintf( "\n" ); } while(0)

#endif // _MDK_BOF

#else

/**
 * @brief Does nothing. Define _MDK_DEBUG to enable its behavior.
 */
#define MDK_LOG_DEBUG( f, ... )

#endif // _MDK_DEBUG

#ifdef _MDK_VERBOSE

#ifdef _MDK_BOF

/**
 * @brief Logs a success message to the beacon console with a timestamp.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_SUCCESS( f, ... ) MdkBeaconPrintf( '+', f, __VA_ARGS__ );

/**
 * @brief Logs an informational message to the beacon console with a timestamp.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_INFO( f, ... ) MdkBeaconPrintf( '*', f, __VA_ARGS__ );

/**
 * @brief Logs a warning message to the beacon console with a timestamp.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_WARNING( f, ... ) MdkBeaconPrintf( '!', f, __VA_ARGS__ );

/**
 * @brief Logs an error message to the beacon console with a timestamp.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_ERROR( f, ... ) MdkBeaconPrintf( '-', f, __VA_ARGS__ );

#else

/**
 * @brief Logs a success message to the console with the calling function name and line number.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_SUCCESS( f, ... ) do { MdkPrintf( "\033[1;32m[+]\033[1;0m %s:%d | ", __FUNCTION__, __LINE__ ); MdkPrintf( f, __VA_ARGS__ ); MdkPrintf( "\n" ); } while(0)

/**
 * @brief Logs an informational message to the console with the calling function name and line number.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_INFO( f, ... ) do { MdkPrintf( "\033[1;34m[*]\033[1;0m %s:%d | ", __FUNCTION__, __LINE__ ); MdkPrintf( f, __VA_ARGS__ ); MdkPrintf( "\n" ); } while(0)

/**
 * @brief Logs a warning message to the console with the calling function name and line number.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_WARNING( f, ... ) do { MdkPrintf( "\033[1;33m[!]\033[1;0m %s:%d | ", __FUNCTION__, __LINE__ ); MdkPrintf( f, __VA_ARGS__ ); MdkPrintf( "\n" ); } while(0)

/**
 * @brief Logs an error message to the console with the calling function name and line number.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_LOG_ERROR( f, ... ) do { MdkPrintf( "\033[1;31m[-]\033[1;0m %s:%d | ", __FUNCTION__, __LINE__ ); MdkPrintf( f, __VA_ARGS__ ); MdkPrintf( "\n" ); } while(0)

#endif // _MDK_BOF

#else

/**
 * @brief Does nothing. Define _MDK_VERBOSE to enable its behavior.
 */
#define MDK_LOG_SUCCESS( f, ... )

/**
 * @brief Does nothing. Define _MDK_VERBOSE to enable its behavior.
 */
#define MDK_LOG_INFO( f, ... )

/**
 * @brief Does nothing. Define _MDK_VERBOSE to enable its behavior.
 */
#define MDK_LOG_WARNING( f, ... )

/**
 * @brief Does nothing. Define _MDK_VERBOSE to enable its behavior.
 */
#define MDK_LOG_ERROR( f, ... )

#endif // _MDK_VERBOSE

/**
 * @brief Logs an error message to the console with the calling function name and line number, then returns with the failure code.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_RET_ERROR( f, ... ) do { MDK_LOG_ERROR( f, __VA_ARGS__ ); return MDK_FAILURE; } while(0)

/**
 * @brief Logs a success message to the console with the calling function name and line number, the returns with the success code.
 *
 * @param f The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
#define MDK_RET_SUCCESS( f, ... ) do { MDK_LOG_SUCCESS( f, __VA_ARGS__ ); return MDK_SUCCESS; } while(0)

#endif // _MDK_LOG_H_
