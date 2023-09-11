import * as fs from 'fs';
import { generateBuildRpmAndDockerImagesConfig } from '../pipeline-build-rpm-and-docker-images';

describe('Build RPM & Docker images workflow tests', () => {
  it.each`
    graviteeioVersion  | isDryRun | dockerTagAsLatest | expectedFileName
    ${'4.1.0-alpha.1'} | ${true}  | ${false}          | ${'build-rpm-and-docker-images-prerelease-dry-run.yml'}
    ${'4.1.0-alpha.1'} | ${false} | ${false}          | ${'build-rpm-and-docker-images-prerelease-no-dry-run.yml'}
    ${'4.1.0'}         | ${true}  | ${false}          | ${'build-rpm-and-docker-images-release-dry-run.yml'}
    ${'4.1.0'}         | ${false} | ${false}          | ${'build-rpm-and-docker-images-release-no-dry-run.yml'}
    ${'4.1.0'}         | ${false} | ${true}           | ${'build-rpm-and-docker-images-release-no-dry-run-as-latest.yml'}
  `(
    'should build RPM & Docker images with $graviteeioVersion and dry run as $isDryRun',
    ({ graviteeioVersion, isDryRun, dockerTagAsLatest, expectedFileName }) => {
      const result = generateBuildRpmAndDockerImagesConfig({
        action: 'build_rpm_&_docker_images',
        branch: 'master',
        sha1: '784ff35ca',
        changedFiles: [],
        buildNum: '1234',
        buildId: '1234',
        graviteeioVersion,
        isDryRun,
        dockerTagAsLatest,
        apimVersionPath: '',
      });

      const expected = fs.readFileSync(`./src/pipelines/tests/resources/build-rpm-and-docker-images/${expectedFileName}`, 'utf-8');
      expect(expected).toStrictEqual(result.stringify());
    },
  );

  it('should throw an error when trying to generate build RPM & Docker images config without graviteeio version', () => {
    expect.assertions(1);

    try {
      generateBuildRpmAndDockerImagesConfig({
        action: 'build_rpm_&_docker_images',
        branch: 'master',
        sha1: '784ff35ca',
        changedFiles: [],
        buildNum: '1234',
        buildId: '1234',
        isDryRun: false,
        graviteeioVersion: '',
        dockerTagAsLatest: false,
        apimVersionPath: '',
      });
    } catch (e) {
      expect(e).toStrictEqual(new Error('Graviteeio version is not defined - Please export CI_GRAVITEEIO_VERSION environment variable'));
    }
  });

  it('should throw an error when trying to generate build RPM & Docker images config without branch', () => {
    expect.assertions(1);

    try {
      generateBuildRpmAndDockerImagesConfig({
        action: 'build_rpm_&_docker_images',
        branch: '',
        sha1: '784ff35ca',
        changedFiles: [],
        buildNum: '1234',
        buildId: '1234',
        isDryRun: false,
        graviteeioVersion: '1.2.3',
        dockerTagAsLatest: false,
        apimVersionPath: '',
      });
    } catch (e) {
      expect(e).toStrictEqual(new Error('A branch (CIRCLE_BRANCH) must be specified'));
    }
  });
});
