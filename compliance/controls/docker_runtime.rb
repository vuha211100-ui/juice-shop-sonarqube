# Runs on the HOST (local transport) and inspects `docker inspect`, so it works with the
# distroless image, which has no shell/ps/stat for the docker:// transport to use.
#   inspec exec compliance --input container=juice-shop-target

container = input('container', value: 'juice-shop-target')
cfg = json(command: "docker inspect #{container}").params.first

control 'pci-2.2-non-root' do
  impact 1.0
  title 'Container runs as a non-root user (PCI-DSS 2.2 / CIS Docker 4.1)'
  describe cfg['Config']['User'] do
    it { should_not be_empty }
    it { should_not match(/^(root|0)(:|$)/) }
  end
end

control 'cis-5.4-least-privilege' do
  impact 1.0
  title 'Not privileged, no new privileges, all capabilities dropped (CIS Docker 5.3/5.4/5.25)'
  describe cfg['HostConfig']['Privileged'] do it { should eq false } end
  describe cfg['HostConfig']['SecurityOpt'] do it { should include 'no-new-privileges:true' } end
  describe cfg['HostConfig']['CapDrop'] do it { should include 'ALL' } end
end

control 'gdpr-32-network-exposure' do
  impact 0.7
  title 'Published ports are bound to loopback only (GDPR Art.32)'
  (cfg['HostConfig']['PortBindings'] || {}).each_value do |binds|
    binds.each { |b| describe b['HostIp'] do it { should eq '127.0.0.1' } end }
  end
end

control 'pci-8.3-no-secrets-in-env' do
  impact 1.0
  title 'No credentials in container environment (PCI-DSS 8.3)'
  describe (cfg['Config']['Env'] || []).grep(/(PASSWORD|SECRET|TOKEN|API_KEY)=/i) do
    it { should be_empty }
  end
end
