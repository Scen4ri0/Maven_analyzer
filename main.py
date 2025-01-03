import argparse
import json
import asyncio
from artifact.artifact_verification import process_artifact
from utils.logging import configure_logging


async def process_all_artifacts(artifacts, check_domain, github_token, use_sandbox, sandbox_api_key):
    """
    Processes all artifacts asynchronously.
    """
    results = []
    for artifact in artifacts:
        try:
            # Асинхронный вызов process_artifact с поддержкой песочницы
            result = await process_artifact(
                artifact,
                check_domain=check_domain,
                github_token=github_token,
                sandbox_api_key=sandbox_api_key if use_sandbox else None  # Условная передача ключа
            )
            results.append(result)

            # Print the result for the current artifact
            print(f"Result for artifact '{artifact}':")
            print(json.dumps(result, indent=4))

        except Exception as e:
            error_message = f"Error processing artifact {artifact}: {e}"
            print(error_message)

    return results


def main():
    """
    Main entry point for processing artifacts.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Verify Maven artifacts.")
    parser.add_argument("input", help="Path to the file containing artifacts to verify or a single artifact in format 'groupId:artifactId:versionId'.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed output.")
    parser.add_argument("-o", "--output", help="Path to output file (optional).")
    parser.add_argument("-d", "--domain", action="store_true", help="Enable domain and publication date checks.")
    parser.add_argument("-s", "--sandbox", action="store_true", help="Enable sandbox scanning (e.g., VirusTotal).")
    parser.add_argument("--sandbox-api-key", help="API key for the sandbox service (e.g., VirusTotal).")
    parser.add_argument("--github-token", help="GitHub API token for authenticated requests.")
    args = parser.parse_args()

    # Configure logging
    configure_logging(verbose=args.verbose)

    # Проверка, нужен ли API-ключ для песочницы
    if args.sandbox and not args.sandbox_api_key:
        print("Error: Sandbox scanning requires an API key. Use --sandbox-api-key to provide it.")
        return

    # Determine if input is a file or single artifact
    input_value = args.input
    if ":" in input_value:
        # Single artifact provided directly
        artifacts = [input_value]
    else:
        # Read artifacts from file
        try:
            with open(input_value, "r") as file:
                artifacts = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"Error: File '{input_value}' not found.")
            return

    # Run the async processing
    results = asyncio.run(
        process_all_artifacts(
            artifacts,
            args.domain,
            args.github_token,
            args.sandbox,
            args.sandbox_api_key
        )
    )

    # Write all results to the specified output file, if provided
    if args.output:
        with open(args.output, "w") as output_file:
            json.dump(results, output_file, indent=4)
        print(f"\nResults written to {args.output}")
    else:
        print("\nFinal Results:")
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
