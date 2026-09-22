"""AI subsystem: provider abstraction, structured prompts, safety layer,
decision engine, memory and the controlled agent.

The AI is a *security analyst and controlled automation agent* — it reasons,
selects registered tools, and produces structured decisions. It never has
arbitrary shell access (spec §8); every action flows through the tool registry
and the safety/policy gates (spec §32).
"""
