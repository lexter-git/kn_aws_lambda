Script per aws lambda per controllare lo stato dei robot Zebra

In caso di error state manda il clear error (5 tentativi) ed al primo tentativo di clear error manda anche in ricarca

Invia notifiche sulla mail di claudio per tutti gli errori.
Invia le notifiche anche a 3 indirizzi KN solo se AMR risulta Offline
Invia notifica email ad altri indirizzi email KN se fatti 5 tentativi di clear error consecutivi sullo stesso AMR
