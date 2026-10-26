#!/bin/bash
tmux kill-session -t rabbithole 2>/dev/null && echo "Stopped." || echo "Not running."
