# Bundler / RubyGems through Jōei

Mirror rubygems.org for a project:

```bash
bundle config mirror.https://rubygems.org http://localhost:8080/rubygems
```

Or set the source directly in the `Gemfile`:

```ruby
source "http://localhost:8080/rubygems"
```

Plain `gem install` (without Bundler):

```bash
gem install rails --source http://localhost:8080/rubygems
```
