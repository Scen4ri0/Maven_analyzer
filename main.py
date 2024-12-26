import argparse
import json
import asyncio
from artifact.artifact_verification import process_artifact
from utils.logging import configure_logging


async def process_all_artifacts(artifacts, check_domain, github_token):
    """
    Processes all artifacts asynchronously.
    """
    results = []
    for artifact in artifacts:
        try:
            # Асинхронный вызов process_artifact
            result = await process_artifact(
                artifact, 
                check_domain=check_domain,
                github_token=github_token
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
    parser = argparse.ArgumentParser(description="Verify Maven artifacts from a file.")
    parser.add_argument("input_file", help="Path to the file containing artifacts to verify.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed output.")
    parser.add_argument("-o", "--output", required=True, help="Path to output file.")
    parser.add_argument("-d", "--domain", action="store_true", help="Enable domain and publication date checks.")
    parser.add_argument("--github-token", help="GitHub API token for authenticated requests.")
    args = parser.parse_args()

    # Configure logging
    configure_logging(verbose=args.verbose)

    # Read artifacts from file
    input_file = args.input_file
    with open(input_file, "r") as file:
        artifacts = [line.strip() for line in file if line.strip()]

    # Run the async processing
    results = asyncio.run(
        process_all_artifacts(artifacts, args.domain, args.github_token)
    )

    # Write all results to the specified output file
    with open(args.output, "w") as output_file:
        json.dump(results, output_file, indent=4)

    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
