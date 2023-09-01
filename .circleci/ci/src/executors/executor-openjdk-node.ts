import { executors, reusable } from '@circleci/circleci-config-sdk';
import { config } from '../config';
import { Executor } from '@circleci/circleci-config-sdk/dist/src/lib/Components/Executors';
import { DockerResourceClass } from '@circleci/circleci-config-sdk/dist/src/lib/Components/Executors/types/DockerExecutor.types';

export class OpenJdkNodeExecutor {
  public static create(resource: DockerResourceClass = config.executor.openjdk.resource): Executor {
    const image = `${config.executor.openjdk.image}:${config.executor.openjdk.version}-node`;
    return new executors.DockerExecutor(image, resource);
  }

  public static get(resource: DockerResourceClass = config.executor.openjdk.resource): reusable.ReusableExecutor {
    return new reusable.ReusableExecutor('openjdk-node', OpenJdkNodeExecutor.create(resource));
  }
}
