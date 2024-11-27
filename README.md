# **Segmented Kernel**
Un noyau 32 bits écrit entièrement en assembleur avec segmentation mémoire pour la gestion des processus.

---

## **Introduction**
**Segmented Kernel** est un noyau minimaliste développé en **assembleur** (FASM) pour architecture **x86**. Il exploite exclusivement la segmentation mémoire, permettant une gestion efficace des processus sans recours à la pagination.  
Ce projet met en œuvre les concepts fondamentaux des systèmes d’exploitation, notamment la gestion des interruptions matérielles, la protection mémoire, et la structure de la GDT (Global Descriptor Table).

---

## **Fonctionnalités**
- **Segmentation mémoire complète** :  
  Utilisation de la **GDT** pour isoler les processus et gérer les segments en mode protégé.
- **Gestion des interruptions matérielles** :  
  Implémentation des ISR (Interrupt Service Routines) pour assurer la communication entre le matériel et le noyau.
- **Privilèges et protection** :  
  Mise en place des niveaux de privilèges pour garantir la sécurité et la stabilité du système.
- **Programmation bas niveau** :  
  Écrit en **assembleur** avec **Flat Assembler (FASM)** pour un contrôle précis des instructions.

---

## **Prérequis**
- **Flat Assembler (FASM)** pour la compilation.
- **Make** pour automatiser la compilation.
- Un **émulateur** ou machine virtuelle compatible **x86** (par exemple : QEMU, Bochs ou VirtualBox).
- **GRUB** pour charger le noyau.

---
