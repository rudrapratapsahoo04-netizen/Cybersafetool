def run_simulation():
    print("\nPHISHING AWARENESS SIMULATOR")
    print("-" * 40)
    print("This is a local, non-credential-collecting training exercise.")
    print("No username/password will be stored or transmitted.\n")

    examples = [
        ("Urgency", "A message says your account will be closed immediately."),
        ("Sender mismatch", "The displayed sender name does not match the address."),
        ("Suspicious link", "The link uses an unrelated or shortened domain."),
        ("Unexpected attachment", "An unexpected attachment asks you to enable macros."),
    ]

    score = 0
    for title, text in examples:
        print(f"\n[{title}] {text}")
        ans = input("What should you do? [1] Verify independently [2] Open it: ").strip()
        if ans == "1":
            score += 1

    print(f"\nAwareness score: {score}/{len(examples)}")
    print("Remember: verify through a trusted channel before acting on unexpected requests.")
