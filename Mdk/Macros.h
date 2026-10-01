/**
 * @file Macros.h
 * @author Ky4meru (@ky4meru)
 * @brief Utility macros.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_MACROS_H_
#define _MDK_MACROS_H_

/**
 * @brief Represents a success status value.
 */
#define MDK_SUCCESS 0

/**
 * @brief Represents an error status value.
 */
#define MDK_FAILURE -1

/**
 * @brief Represents a handle to the current process.
 */
#define MdkCurrentProcess( ) ( ( HANDLE ) ( LONG_PTR ) -1 )

/**
 * @brief Represents a handle to the current thread.
 */
#define MdkCurrentThread( ) ( ( HANDLE ) ( LONG_PTR ) -2 )

/**
 * @brief Decorates assembly inline functions.
 */
#define MDK_INLINE_ASSEMBLY __attribute__( ( naked ) )

/**
 * @brief Casts a value to an unsigned pointer-wide integer value.
 *
 * @param p The value to cast.
 * @return The same value cast as an unsigned pointer-wide integer value.
 */
#define MDK_CAST_UPTR( p ) ( ( ULONG_PTR ) ( p ) ) 

/**
 * @brief Casts a value to a VOID pointer.
 * 
 * @param p The value to cast.
 * @return The same value cast as a VOID pointer.
 */
#define MDK_CAST_VPTR( p ) ( ( LPVOID ) ( MDK_CAST_UPTR( p ) ) )

/**
 * @brief Casts a value to a signed long.
 * 
 * @param x The value to cast.
 * @return The same value cast as a signed integer.
 */
#define MDK_CAST_SINT( x ) ( ( LONG ) ( MDK_CAST_UPTR( x ) ) )

/**
 * @brief Casts a value to an unsigned long.
 * 
 * @param x The value to cast.
 * @return The same value cast as an unsigned integer.
 */
#define MDK_CAST_UINT( x ) ( ( DWORD ) ( MDK_CAST_UPTR( x ) ) )

/**
 * @brief Checks if a status value is a success.
 *
 * @param s The status value to check.
 * @return True if the value represents a success, false otherwise.
 */
#define MDK_SUCCEEDED( s ) ( ( ( NTSTATUS ) MDK_CAST_UPTR( s ) ) >= MDK_SUCCESS )

/**
 * @brief Expands the provided arguments.
 * 
 * @param ... The arguments to expand.
 * @return The literal expansion of the parameters.
 */
#define MDK_EXPAND( ... ) __VA_ARGS__

/**
* @brief Converts any value into a literal string.
* 
* @param s The value to convert into a string.
* @return The literal string.
*/
#define MDK_CAST_LSTR( s ) #s

/**
 * @brief Invokes a macro by doing an expansion.
 * 
 * @param m The macro to call.
 * @param a The arguments passed to the macro.
 * @return The value returned by the macro (if any).
 */
#define MDK_CALL_MACRO( m, a ) m( a )

/**
 * @brief Invokes a procedure (function or syscall) with its arguments.
 * 
 * This macro casts the procedure to a generic function pointer to be able to invoke it even if its prototype is not declared in the current scope.
 *
 * @param p The pointer to the procedure to invoke.
 * @param ... The arguments to pass to th the procedure.
 * @return The value returned by the procedure. It must be cast.
 */
#define MDK_CALL_PROC( p, ... )  ( ( LPVOID ( * ) ( ... ) ) p ) ( __VA_ARGS__ )

/**
 * @brief Concatenates two strings.
 * 
 * @param l The first string the concatenate.
 * @param r The second string to concatenate.
 * @return The concatenation of the two strings.
 */
#define MDK_CONCAT_STR( l, r ) l ## r

/**
 * @brief Declares a function pointer using its own type.
 * 
 * This shall be only used in a structure, to avoid function redefinition.
 * 
 * @param f The name of the function pointer to declare.
 * @return None.
 */
#define MDK_DECL_TYPE( f ) decltype( &f ) f

/**
 * @brief Declares an imported function pointer using its own type.
 * 
 * This macro is particularly useful when developing Beacon Object Files.
 * 
 * @param m The module in which the function is coded.
 * @param f The name of the function pointer to declare.
 * @return None.
 */
#define MDK_DECL_SPEC( m, f ) DECLSPEC_IMPORT decltype( f ) m ## $ ## f

/**
 * @brief Declares a hash for a string in the current scope.
 * 
 * @param n The name of the hash. It will automatically be prefixed with MDK_HASH_.
 * @param s The string to be hashed.
 * @return None.
 */
#define MDK_DECL_HASH( n, s ) constexpr DWORD MDK_CONCAT_STR( MDK_HASH_, n ) = MdkCompileTimeHashString( s )

/**
 * @brief Declares a hash for a procedure (function or syscall) in the current scope.
 * 
 * @param p The name of the procedure for which a hash is declared.
 * @return None.
 */
#define MDK_DECL_PROC( p ) MDK_DECL_HASH( p, MDK_CAST_LSTR( p ) )

/**
 * @brief Declares a hash for a dll in the current scope.
 *
 * @param d The name of the dll for which a hash is declared. Do not add ".dll" at the end, it is done automatically.
 * @return None.
 */
#define MDK_DECL_DLL( d ) MDK_DECL_HASH( d, MDK_CAST_LSTR( d ) ".dll" )

/**
 * @brief Declares a hash for a PE section in the current scope.
 * 
 * @param s The name of the section for which a hash is declared.
 * @return None.
 */
#define MDK_DECL_SEC( s ) MDK_DECL_HASH( s, "." MDK_CAST_LSTR( s ) )

/**
 * @brief Dynamically gets the pointer to a procedure (function or syscall).
 *
 * @param m The module name that exports the procedure. An associated hash must be declared in the current scope.
 * @param p The procedure name to get. An associated hash must be declared in the current scope.
 * @return The pointer to the procedure.
 */
#define MDK_GET_PROC( m, p ) MdkGetProcAddressByHash( MdkGetModuleHandleByHash( MDK_CONCAT_STR( MDK_HASH_, m ) ), MDK_CONCAT_STR( MDK_HASH_, p ) )

/**
 * @brief Dynamically gets the pointer to a syscall. The hash for "Ntdll.dll" must be declared in the current scope.
 *
 * @param s The syscall name to get.
 * @return The pointer to the syscall stub.
 */
#define MDK_GET_SYSCALL( s ) MDK_GET_PROC( Ntdll, s )

#ifdef _MDK_PIC
/**
 * @brief Decorates a function to place it in a specific section of the .text region in the compiled PE.
 * 
 * Only when _MDK_PIC is defined.
 *
 * @param x The name of the section.
 * @return None.
 */
#define MDK_TEXT_SEC( x ) __attribute__( ( section( ".text$" #x ) ) )
#else
/**
 * @brief Does nothing.
 * 
 * Define _MDK_PIC to enable its behavior.
 */
#define MDK_TEXT_SEC( x )
#endif // _MDK_PIC

/// @private
#define __MDK_INDIRECT_SYSCALL_X( s ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_A( s, a ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_B( s, a, b ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_C( s, a, b, c ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_D( s, a, b, c, d ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_E( s, a, b, c, d, e ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_F( s, a, b, c, d, e, f ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_G( s, a, b, c, d, e, f, g ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_H( s, a, b, c, d, e, f, g, h ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), NULL, NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_I( s, a, b, c, d, e, f, g, h, i ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), NULL, NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_J( s, a, b, c, d, e, f, g, h, i, j ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), MDK_CAST_VPTR( j ), NULL, NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_K( s, a, b, c, d, e, f, g, h, i, j, k ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), MDK_CAST_VPTR( j ), MDK_CAST_VPTR( k ), NULL )
/// @private
#define __MDK_INDIRECT_SYSCALL_L( s, a, b, c, d, e, f, g, h, i, j, k, l ) MdkIndirectSyscall( MDK_CONCAT_STR( MDK_HASH_, s ), MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), MDK_CAST_VPTR( j ), MDK_CAST_VPTR( k ), MDK_CAST_VPTR( l ) )
/// @private
#define __MDK_INDIRECT_SYSCALL( a, b, c, d, e, f, g, h, i, j, k, l, s, ... ) s

/**
 * @brief Invokes an indirect syscall using the Hell's Hall and Tartarus Gate techniques.
 * 
 * The hash for the syscall name must be declared in the current scope.
 *
 * @param s The name of the native syscall to invoked.
 * @param ... The parameters of the syscall.
 * @return The value returned by the syscall.
 */
#define MDK_INDIRECT_SYSCALL( s, ... ) __MDK_INDIRECT_SYSCALL( __VA_ARGS__, __MDK_INDIRECT_SYSCALL_L, __MDK_INDIRECT_SYSCALL_K, __MDK_INDIRECT_SYSCALL_J, __MDK_INDIRECT_SYSCALL_I, __MDK_INDIRECT_SYSCALL_H, __MDK_INDIRECT_SYSCALL_G, __MDK_INDIRECT_SYSCALL_F, __MDK_INDIRECT_SYSCALL_E, __MDK_INDIRECT_SYSCALL_D, __MDK_INDIRECT_SYSCALL_C, __MDK_INDIRECT_SYSCALL_B, __MDK_INDIRECT_SYSCALL_A, __MDK_INDIRECT_SYSCALL_X )( s, __VA_ARGS__ )

/// @private
#define __MDK_SPOOF_CALL_X( p, n ) MdkSpoofCall( p, n, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_A( p, n, a ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_B( p, n, a, b ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_C( p, n, a, b, c ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_D( p, n, a, b, c, d ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_E( p, n, a, b, c, d, e ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), NULL, NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_F( p, n, a, b, c, d, e, f ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), NULL, NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_G( p, n, a, b, c, d, e, f, g ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), NULL, NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_H( p, n, a, b, c, d, e, f, g, h ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), NULL, NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_I( p, n, a, b, c, d, e, f, g, h, i ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), NULL, NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_J( p, n, a, b, c, d, e, f, g, h, i, j ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), MDK_CAST_VPTR( j ), NULL, NULL )
/// @private
#define __MDK_SPOOF_CALL_K( p, n, a, b, c, d, e, f, g, h, i, j, k ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), MDK_CAST_VPTR( j ), MDK_CAST_VPTR( k ), NULL )
/// @private
#define __MDK_SPOOF_CALL_L( p, n, a, b, c, d, e, f, g, h, i, j, k, l ) MdkSpoofCall( p, n, MDK_CAST_VPTR( a ), MDK_CAST_VPTR( b ), MDK_CAST_VPTR( c ), MDK_CAST_VPTR( d ), MDK_CAST_VPTR( e ), MDK_CAST_VPTR( f ), MDK_CAST_VPTR( g ), MDK_CAST_VPTR( h ), MDK_CAST_VPTR( i ), MDK_CAST_VPTR( j ), MDK_CAST_VPTR( k ), MDK_CAST_VPTR( l ) )
/// @private
#define __MDK_SPOOF_CALL( a, b, c, d, e, f, g, h, i, j, k, l, s, ... ) s

/**
 * @brief Invokes a procedure with call stack spoofing.
 *
 * The call stack is spoofed using a trampoline gadget found in KernelBase.dll. The spoofed frames mimic a legitimate
 * BaseThreadInitThunk to RtlUserThreadStart chain.
 *
 * @param p The pointer to the procedure to invoke.
 * @param n The syscall number. Pass 0 if the procedure is not a syscall.
 * @param ... The parameters of the procedure.
 * @return The value returned by the procedure.
 */
#define MDK_SPOOF_CALL( p, n, ... ) __MDK_SPOOF_CALL( __VA_ARGS__, __MDK_SPOOF_CALL_L, __MDK_SPOOF_CALL_K, __MDK_SPOOF_CALL_J, __MDK_SPOOF_CALL_I, __MDK_SPOOF_CALL_H, __MDK_SPOOF_CALL_G, __MDK_SPOOF_CALL_F, __MDK_SPOOF_CALL_E, __MDK_SPOOF_CALL_D, __MDK_SPOOF_CALL_C, __MDK_SPOOF_CALL_B, __MDK_SPOOF_CALL_A, __MDK_SPOOF_CALL_X )( p, n, __VA_ARGS__ )

#endif // _MDK_MACROS_H_
