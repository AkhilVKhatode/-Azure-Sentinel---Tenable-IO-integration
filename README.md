# Tenable Sentinel Connector

## Overview

The Tenable Sentinel Connector is a Python-based Azure Function designed to integrate with Tenable.io and Azure Log Analytics. This connector collects data from Tenable.io, including vulnerabilities, assets, and plugins, and sends it to Azure Log Analytics for further analysis and monitoring. It supports configurable intervals and filtering based on severity levels and other parameters.

## Features

- **Data Collection**: Collects vulnerabilities, assets, and plugins from Tenable.io.
- **Data Transformation**: Transforms and formats data to fit the schema required by Azure Log Analytics.
- **Configurable**: Allows configuration of parameters like severity levels, sync plugins, and fixed vulnerabilities.
- **Scheduled Execution**: Uses cron-like scheduling for data collection intervals.
- **Error Handling**: Provides detailed error logging and handling.

## Prerequisites

- **Python 3.7+**: Ensure you have Python 3.7 or higher installed.
- **Azure Function App**: Deployed as an Azure Function.
- **Tenable.io Account**: Requires Tenable.io credentials (Access Key and Secret Key).
- **Azure Log Analytics**: Requires Workspace ID and Workspace Key for data ingestion.

## Environment Variables

The connector uses the following environment variables:

- `TenableAccessKey`: Your Tenable.io Access Key.
- `TenableSecretKey`: Your Tenable.io Secret Key.
- `WorkspaceID`: Your Azure Log Analytics Workspace ID.
- `WorkspaceKey`: Your Azure Log Analytics Workspace Key.
- `AzureWebJobsStorage`: Connection string for Azure Storage.
- `logAnalyticsUri`: URI for Log Analytics.
- `StartTime`: Start date for data collection in `MM/DD/YYYY HH:MM:SS` format.
- `LowestSeverity`: Minimum severity level for data collection (`info`, `low`, `medium`, `high`, `critical`).
- `TenableTags`: Tags to filter Tenable.io data.
- `FixedVulnerability`: Whether to collect data on fixed vulnerabilities (`True` or `False`).
- `Interval`: Cron-like schedule for data collection.
- `SyncPlugins`: Whether to sync plugins (`True` or `False`).
- `VerifySSL`: Whether to verify SSL certificates (`True` or `False`).
- `Address`: Tenable.io API endpoint address.

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   ```
2. Install the required Python packages:
  ```
  pip install -r requirements.txt
  ```
3. Set up the environment variables as listed in the Environment Variables section.
4. Deploy the function to Azure or run it locally using Azure Functions Core Tools.

### Usage
The connector is designed to be used as an Azure Function. It collects data from Tenable.io at specified intervals and sends it to Azure Log Analytics. Ensure that the Azure Function is properly configured with the necessary environment variables and permissions.

### Code Structure
  - init.py: Contains the main logic for the Tenable Sentinel Connector, including data collection, transformation, and posting to Azure Log Analytics.
  - state_manager.py: Manages state and checkpoints for data collection (included but not detailed here).
  - requirements.txt: Lists the Python dependencies required by the project.
