import sys

import normal_traffic
import attack_sql_injection
import attack_brute_force
import attack_bola
import attack_flooding
import attack_credential_stuffing
import attack_parameter_tampering
import attack_token_replay


def main(scale):
    print("=" * 50)
    print(f"APISentry dataset generation (scale={scale})")
    print("=" * 50)
    normal_traffic.run(scale * 100)
    attack_sql_injection.run(scale * 8)
    attack_brute_force.run(scale * 8)
    attack_bola.run(scale * 8)
    attack_flooding.run(scale * 4)
    attack_credential_stuffing.run(scale * 30)
    attack_parameter_tampering.run(scale * 8)
    attack_token_replay.run(scale * 8)
    print("=" * 50)
    print("All traffic generation complete.")
    print("=" * 50)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
