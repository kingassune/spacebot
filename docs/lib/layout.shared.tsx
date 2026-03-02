import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

// James GitHub repository
export const gitConfig = {
  user: 'spacedriveapp',
  repo: 'james',
  branch: 'main',
};

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: 'James',
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
  };
}
