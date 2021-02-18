# Rbshark

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/rbshark`. To experiment with that code, run `bin/console` for an interactive prompt.

TODO: Delete this and the text above, and describe your gem

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rbshark'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install rbshark

## Usage

TODO: Write usage instructions here

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Sample
### Use Docker
```
cd sample_docker

docker-compose build
docker-compose up -d

docker exec -it sample_docker_node1_1 /bin/sh
  source /etc/profile.d/rbenv.sh
  cd rbshark/
  bundle install
  bundle exec exe/rbshark -i eth0

docker exec -it sample_docker_node2_1 /bin/sh
  ping <node1 IP Addr>
```

### Use Vagrant
```
vagrant up

vagrant ssh node1
  [please set rbenv]
  cd /vagrant
  bundle install
  bundle exec exe/rbshark -i eth1

vagrant ssh node2
  ping 192.168.33.11
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/rbshark.

- [ ] aaaa

