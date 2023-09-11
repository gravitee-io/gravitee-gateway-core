import { commands, Config, Job, parameters, reusable } from '@circleci/circleci-config-sdk';
import { Command } from '@circleci/circleci-config-sdk/dist/src/lib/Components/Commands/exports/Command';
import { CommandParameterLiteral } from '@circleci/circleci-config-sdk/dist/src/lib/Components/Parameters/types/CustomParameterLiterals.types';
import { NodeLtsExecutor } from '../../executors';
import { NotifyOnFailureCommand, WebuiInstallCommand } from '../../commands';

export class WebuiLintTestJob {
  private static jobName = 'job-webui-lint-test';

  private static customParametersList = new parameters.CustomParametersList<CommandParameterLiteral>([
    new parameters.CustomParameter('apim-ui-project', 'string', '', 'the name of the UI project to build'),
    new parameters.CustomParameter('resource_class', 'string', 'medium', 'Resource class to use for executor'),
  ]);

  public static create(dynamicConfig: Config): Job {
    const webUiInstallCommand = WebuiInstallCommand.get();
    dynamicConfig.addReusableCommand(webUiInstallCommand);

    const notifyOnFailureCommand = NotifyOnFailureCommand.get(dynamicConfig);
    dynamicConfig.addReusableCommand(notifyOnFailureCommand);

    const steps: Command[] = [
      new commands.Checkout(),
      new reusable.ReusedCommand(webUiInstallCommand, { 'apim-ui-project': '<< parameters.apim-ui-project >>' }),
      new commands.workspace.Attach({ at: '.' }),
      new commands.Run({
        name: 'Check License',
        command: 'npm run lint:license',
        working_directory: '<< parameters.apim-ui-project >>',
      }),
      new commands.Run({
        name: 'Run Prettier and ESLint',
        command: 'npm run lint',
        working_directory: '<< parameters.apim-ui-project >>',
      }),
      new commands.Run({
        name: 'Run unit tests',
        command: 'npm run test:coverage',
        working_directory: '<< parameters.apim-ui-project >>',
      }),
      new reusable.ReusedCommand(notifyOnFailureCommand),
      // For Sonar analysis
      new commands.workspace.Persist({
        root: '.',
        paths: ['<< parameters.apim-ui-project >>/coverage/lcov.info'],
      }),
      // For direct access in CircleCI UI
      new commands.StoreArtifacts({
        path: '<< parameters.apim-ui-project >>/coverage/lcov.info',
      }),
    ];

    return new reusable.ParameterizedJob(
      WebuiLintTestJob.jobName,
      NodeLtsExecutor.create('<< parameters.resource_class >>'),
      WebuiLintTestJob.customParametersList,
      steps,
    );
  }
}
