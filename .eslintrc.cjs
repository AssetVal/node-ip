module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    tsconfigRootDir: __dirname,
    project: [
      './tsconfig.json',
    ],
    ecmaVersion: 'latest',
  },
  'env': {
    'browser': true,
    'commonjs': true,
    'es2022': true
  },
  extends: [
    'eslint:recommended',
    'airbnb-base',
    'airbnb-typescript/base',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-type-checked',
    'plugin:@typescript-eslint/stylistic-type-checked',
    'plugin:n/recommended',
    'plugin:security/recommended',
    'plugin:import/typescript',
    'plugin:@getify/proper-ternary/getify-says',
    'prettier',
  ],
  plugins: [
    '@typescript-eslint',
    'n',
    'security',
    '@getify/proper-ternary',
  ],
  'rules': {
    'indent': [
      'error',
      2
    ],
    'linebreak-style': [
      'error',
      'unix'
    ],
    'quotes': [
      'error',
      'single'
    ],
    'semi': [
      'error',
      'always'
    ]
  }
};
