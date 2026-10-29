# Keep rules for an Android app that bundles libspry_relay.so.
#
# The library exports Java_dev_forgesworn_spry_SpryRelayNative_* and the JVM
# binds them by the class's name and each native method's name and
# descriptor, which R8 cannot see. Keep both. The library never calls back
# into Java (no FindClass, GetMethodID or callbacks), so nothing else is
# reached from native code. Byte arrays and strings are platform types.
-keepclasseswithmembernames,includedescriptorclasses class dev.forgesworn.spry.SpryRelayNative {
    native <methods>;
}
-keep class dev.forgesworn.spry.SpryRelayNative
