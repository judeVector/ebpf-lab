# eBPF Labs

> A hands-on lab environment for learning and experimenting with **eBPF** across different programming languages.

---

## What is eBPF?

**eBPF (extended Berkeley Packet Filter)** is a technology in the Linux kernel that allows you to run sandboxed programs inside the kernel without writing kernel modules. It lets developers hook into kernel events (like network packets, system calls, tracing points, etc.) and run custom logic safely — enabling things like high-speed packet filtering, observability, tracing, and performance monitoring.

---

## About This Repo

This repo contains eBPF programs implemented in **Rust**, **C**, and **Python**, using tools like Aya (Rust), libbpf (C), and BCC (Python). The goal is to explore how eBPF works across different ecosystems — from packet filtering with XDP to tracing and metrics collection.

---

## Features

- ✅ XDP programs in Rust (using Aya)
- ✅ eBPF programs and loaders in C + libbpf
- ✅ Simple tracing scripts in Python using BCC
- 🚧 More examples on the way...

---

## Why this repo?

I'm learning eBPF hands-on and building experiments across multiple languages to truly understand how it works under the hood. This repo serves as both practice and reference for others who want to follow along.
