#!/bin/bash
# Starts RabbitHole inside a tmux session so it keeps running after you
# disconnect, while still letting you attach and watch live output exactly
# like running it in the foreground.
cd "$(dirname "$0")"
SESSION=rabbithole

tmux kill-session -t "$SESSION" 2>/dev/null
sleep 1

tmux new-session -d -s "$SESSION" \
  "source rabhole/bin/activate; set -a; source .env; set +a; python app.py"

echo "Started RabbitHole in tmux session '$SESSION'."
echo "  Watch live logs:        tmux attach -t $SESSION"
echo "  Detach (keeps running): press Ctrl+B then D"
echo "  Stop it:                ./stop_app.sh"
