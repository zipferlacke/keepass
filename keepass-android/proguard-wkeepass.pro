# Was nur über JNI gerufen wird, sieht der Optimierer als unbenutzt an —
# und wirft es aus der Release-APK. Die Debug-Fassung merkt davon nichts,
# der Fehler fiele also erst beim fertigen Build auf.
-keep class de.wuefl.wkeepass.sicherheit.** { *; }
