# Was nur über JNI gerufen wird oder JNI-Funktionen trägt, sieht der
# Optimierer als unbenutzt an — und wirft es aus der Release-APK oder
# benennt es um. Dann findet Rust die Klasse nicht mehr, oder die Klasse
# ihre Rust-Funktion nicht. Die Debug-Fassung merkt davon nichts, der
# Fehler fiele also erst beim fertigen Build auf.
-keep class de.wuefl.wkeepass.sicherheit.** { *; }
-keep class de.wuefl.wkeepass.kern.** { *; }
-keep class de.wuefl.wkeepass.system.** { *; }
